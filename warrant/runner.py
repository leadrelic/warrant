"""
Tool execution. The only place a subprocess is started.

Flow for every run: validate params -> scope-check every target -> audit -> execute
(argv list, no shell) -> save raw output as evidence -> parse -> record findings -> audit.
The CLI and the web GUI both call ToolRunner, so they enforce exactly the same rules.
"""

import hashlib
import os
import shutil
import signal
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from .engagement import Engagement
from .scope import Decision
from .validate import Param, ValidationError, validate_params


class ScopeViolation(Exception):
    def __init__(self, decisions):
        self.decisions = decisions
        super().__init__("; ".join(f"{d.target}: {d.reason}" for d in decisions))


class ToolMissing(Exception):
    pass


class NoEngagement(Exception):
    pass


class Cancelled(Exception):
    pass


@dataclass
class ToolSpec:
    id: str
    label: str
    category: str
    description: str
    params: List[Param]
    binary: Optional[str] = None              # external executable (None for built-in tools)
    build: Optional[Callable] = None          # (clean, ctx) -> argv list
    run: Optional[Callable] = None            # built-in: (clean, ctx) -> iterable of output lines
    parse: Optional[Callable] = None          # (ctx) -> list of finding-draft dicts
    outputs: Dict[str, str] = field(default_factory=dict)   # name -> file suffix created in the evidence dir
    timeout: int = 3600
    needs_root: bool = False
    install: str = ""
    alt_binaries: tuple = ()

    def resolve_binary(self) -> Optional[str]:
        for name in (self.binary,) + tuple(self.alt_binaries):
            if name and shutil.which(name):
                return shutil.which(name)
        return None

    def available(self) -> bool:
        return self.binary is None or self.resolve_binary() is not None

    def to_dict(self):
        return {"id": self.id, "label": self.label, "category": self.category, "description": self.description,
                "params": [p.to_dict() for p in self.params], "builtin": self.binary is None,
                "available": self.available(), "needs_root": self.needs_root, "install": self.install}


class RunContext:
    """Passed to build/run/parse callbacks."""

    def __init__(self, spec: ToolSpec, engagement: Optional[Engagement], evidence_dir: Path, stamp: str, cancel: threading.Event):
        self.spec, self.engagement, self.evidence_dir, self.stamp = spec, engagement, evidence_dir, stamp
        self.cancel = cancel
        self.output = ""                       # full captured stdout/stderr
        self.drafts: List[dict] = []           # findings emitted by built-in tools
        self.paths = {k: evidence_dir / f"{stamp}_{spec.id}{suffix}" for k, suffix in spec.outputs.items()}
        self.binary = spec.resolve_binary()

    def check_cancel(self):
        if self.cancel.is_set():
            raise Cancelled()

    def draft(self, **kw):
        self.drafts.append(kw)


@dataclass
class RunResult:
    tool: str
    status: str                  # done | failed | cancelled | timeout
    returncode: Optional[int]
    duration: float
    output_file: Optional[str]
    findings: list
    warnings: List[str] = field(default_factory=list)


class ToolRunner:
    def __init__(self, engagement: Optional[Engagement], registry: Dict[str, ToolSpec], unscoped: bool = False):
        """engagement=None only works with unscoped=True (explicit operator choice)."""
        if engagement is None and not unscoped:
            raise NoEngagement("No active engagement. Create or select one, or pass --no-engagement to run unscoped.")
        self.eng, self.registry, self.unscoped = engagement, registry, unscoped

    # ---------- preparation (no side effects besides scope audit) ----------
    def prepare(self, tool_id: str, raw: dict):
        spec = self.registry.get(tool_id)
        if spec is None:
            raise ValidationError(f"unknown tool '{tool_id}'")
        clean, targets = validate_params(spec.params, raw)
        decisions = []
        if self.eng is not None:
            problem = self.eng.window_error()
            if problem:
                self.eng.audit("scope", "BLOCKED", f"{tool_id} outside engagement window: {problem}")
                raise ScopeViolation([Decision(False, problem, "*")])
            scope = self.eng.scope
            decisions = [scope.check(t) for t in targets]
            denied = [d for d in decisions if not d.allowed]
            if denied:
                self.eng.audit("scope", "BLOCKED", f"{tool_id} {', '.join(f'{d.target} ({d.reason})' for d in denied)}")
                raise ScopeViolation(denied)
        return spec, clean, targets, decisions

    # ---------- execution ----------
    def run(self, tool_id: str, raw: dict, on_line: Optional[Callable[[str], None]] = None,
            cancel: Optional[threading.Event] = None, record_findings: bool = True) -> RunResult:
        spec, clean, targets, decisions = self.prepare(tool_id, raw)
        cancel = cancel or threading.Event()
        if spec.binary and spec.resolve_binary() is None:
            raise ToolMissing(f"'{spec.binary}' is not installed. {spec.install}".strip())

        emit = on_line or (lambda s: None)
        self._recheck_dns(tool_id, targets, decisions, emit)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        evidence_dir = self.eng.evidence_dir if self.eng else Path(tempfile.mkdtemp(prefix="warrant_"))
        ctx = RunContext(spec, self.eng, evidence_dir, stamp, cancel)
        warnings = [w for d in decisions for w in d.warnings]
        for w in warnings:
            emit(f"[!] {w}")

        argv = spec.build(clean, ctx) if spec.build else None
        if argv is not None:
            argv = [str(a) for a in argv]
        resolved = {d.target: d.resolved for d in decisions if d.resolved}
        if self.eng:
            self.eng.audit("tool", "run_start", f"{spec.id} params={_redact(clean)} argv={argv} resolved={resolved}")

        started = time.time()
        lines: List[str] = []
        status, rc = "done", None
        try:
            if argv is not None:
                rc, status = self._exec(argv, spec, lines, emit, cancel)
            else:
                for line in spec.run(clean, ctx):
                    lines.append(line)
                    emit(line)
                    ctx.check_cancel()
        except Cancelled:
            status = "cancelled"
        except Exception as e:                       # built-in tool failure
            status = "failed"
            msg = f"[x] {type(e).__name__}: {e}"
            lines.append(msg)
            emit(msg)
        ctx.output = "\n".join(lines)

        out_file = None
        if self.eng:
            out_file = self.eng.save_evidence(f"{stamp}_{spec.id}.txt", ctx.output + "\n")
        findings = []
        if status == "done" or (status == "failed" and ctx.drafts):
            try:
                drafts = list(ctx.drafts)
                if spec.parse:
                    drafts += spec.parse(ctx) or []
                if record_findings and self.eng:
                    rel = [str(Path("evidence") / p.name) for p in [out_file] + list(ctx.paths.values()) if p and Path(p).exists()]
                    for d in drafts:
                        findings.append(self.eng.add_finding(source=spec.id, evidence=rel, **d))
            except Exception as e:
                msg = f"[x] result parsing failed: {type(e).__name__}: {e}"
                emit(msg)
                warnings.append(msg)
        if self.eng:
            digests = {Path(p).name: _sha256(p) for p in ([out_file] if out_file else []) + list(ctx.paths.values()) if p and Path(p).exists()}
            self.eng.audit("tool", "run_end", f"{spec.id} status={status} rc={rc} findings={len(findings)} sha256={digests}")
        return RunResult(spec.id, status, rc, time.time() - started, str(out_file) if out_file else None, findings, warnings)

    def _recheck_dns(self, tool_id, targets, decisions, emit):
        """Re-resolve hostnames right before launch: a name that moved out of scope since the first check is blocked."""
        if self.eng is None:
            return
        scope = self.eng.scope
        for first in decisions:
            if not first.resolved:
                continue
            again = scope.check(first.target)
            if not again.allowed:
                self.eng.audit("scope", "BLOCKED", f"{tool_id} {first.target} changed resolution: {again.reason} {again.resolved}")
                raise ScopeViolation([again])
            if set(again.resolved) != set(first.resolved):
                emit(f"[!] {first.target} now resolves to {', '.join(again.resolved)} (was {', '.join(first.resolved)}); still in scope")
                first.resolved = again.resolved

    def _exec(self, argv, spec, lines, emit, cancel):
        kwargs = {}
        if os.name == "posix":
            kwargs["start_new_session"] = True
        else:
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    text=True, encoding="utf-8", errors="replace", bufsize=1, shell=False, **kwargs)
        except OSError as e:
            raise ToolMissing(f"could not start {argv[0]}: {e}") from None

        state = {"timeout": False}

        def watchdog():
            deadline = time.time() + spec.timeout
            while proc.poll() is None:
                if cancel.is_set() or time.time() > deadline:
                    state["timeout"] = not cancel.is_set()
                    _kill(proc)
                    return
                time.sleep(0.25)

        threading.Thread(target=watchdog, daemon=True).start()
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\r\n")
            if len(line) > 4000:
                line = line[:4000] + " …[truncated]"
            lines.append(line)
            emit(line)
        proc.wait()
        if cancel.is_set():
            return proc.returncode, "cancelled"
        if state["timeout"]:
            return proc.returncode, "timeout"
        return proc.returncode, ("done" if proc.returncode == 0 else "failed")


def _kill(proc):
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        else:
            proc.terminate()
    except (ProcessLookupError, OSError):
        return
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass


def _sha256(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()[:16]


def _redact(clean: dict) -> dict:
    return {k: v for k, v in clean.items()}
