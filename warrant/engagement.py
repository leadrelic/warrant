"""Engagements: scope, findings, evidence, and a hash-chained audit log."""

import hashlib
import json
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import List, Optional

from . import paths
from .scope import Decision, Scope, TargetError, validate_scope_item

SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["open", "confirmed", "remediated", "accepted", "false_positive"]
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_LOCK = threading.RLock()


class EngagementError(ValueError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    description: str = ""
    affected: str = ""
    recommendation: str = ""
    cve: str = ""
    cvss: str = ""
    status: str = "open"
    source: str = "manual"
    evidence: List[str] = field(default_factory=list)
    created: str = ""
    updated: str = ""

    def to_dict(self):
        return asdict(self)


def check_name(name: str) -> str:
    if not NAME_RE.match(name or ""):
        raise EngagementError("Engagement name must be 1-64 chars: letters, digits, '.', '_', '-' (no leading symbol)")
    return name


class Engagement:
    def __init__(self, name, client="", tester="", description="", start_date="", end_date="",
                 includes=None, excludes=None, allow_unscoped=False, findings=None, created=""):
        self.name = check_name(name)
        self.client, self.tester, self.description = client, tester, description
        self.start_date = start_date or datetime.now().strftime("%Y-%m-%d")
        self.end_date = end_date
        self.includes: List[str] = list(includes or [])
        self.excludes: List[str] = list(excludes or [])
        self.allow_unscoped = allow_unscoped
        self.findings: List[Finding] = list(findings or [])
        self.created = created or now()

    # ---------- paths ----------
    @property
    def dir(self) -> Path:
        return paths.engagements_dir() / self.name

    @property
    def evidence_dir(self) -> Path:
        return paths.secure_mkdir(self.dir / "evidence")

    @property
    def reports_dir(self) -> Path:
        return paths.secure_mkdir(self.dir / "reports")

    # ---------- persistence ----------
    def to_dict(self):
        return {
            "name": self.name, "client": self.client, "tester": self.tester, "description": self.description,
            "start_date": self.start_date, "end_date": self.end_date, "includes": self.includes,
            "excludes": self.excludes, "allow_unscoped": self.allow_unscoped, "created": self.created,
            "findings": [f.to_dict() for f in self.findings],
        }

    def save(self) -> None:
        with _LOCK:
            paths.write_private(self.dir / "engagement.json", json.dumps(self.to_dict(), indent=2))

    @classmethod
    def create(cls, name, **kw) -> "Engagement":
        with _LOCK:
            eng = cls(name, **kw)
            if (eng.dir / "engagement.json").exists():
                raise EngagementError(f"Engagement '{name}' already exists")
            for item in eng.includes + eng.excludes:
                validate_scope_item(item)
            for d in (eng.start_date, eng.end_date):
                if d:
                    try:
                        date.fromisoformat(d)
                    except ValueError:
                        raise EngagementError(f"dates must be YYYY-MM-DD, got {d!r}") from None
            eng.save()
            eng.audit("system", "engagement_created", f"client={eng.client!r} tester={eng.tester!r}")
            return eng

    @classmethod
    def load(cls, name) -> "Engagement":
        check_name(name)
        path = paths.engagements_dir() / name / "engagement.json"
        if not path.exists():
            raise EngagementError(f"Engagement '{name}' not found")
        d = json.loads(path.read_text(encoding="utf-8"))
        findings = [Finding(**f) for f in d.pop("findings", [])]
        return cls(findings=findings, **d)

    # ---------- authorization window ----------
    def window_error(self, today: Optional[date] = None) -> Optional[str]:
        """Reason runs are not allowed right now, or None. Dates are inclusive (YYYY-MM-DD)."""
        today = today or date.today()
        try:
            if self.start_date and today < date.fromisoformat(self.start_date):
                return f"engagement starts {self.start_date}"
            if self.end_date and today > date.fromisoformat(self.end_date):
                return f"engagement ended {self.end_date}"
        except ValueError:
            return f"invalid engagement dates ({self.start_date!r} - {self.end_date!r})"
        return None

    # ---------- scope ----------
    @property
    def scope(self) -> Scope:
        return Scope(self.includes, self.excludes, self.allow_unscoped)

    def add_scope(self, item: str, exclude: bool = False) -> str:
        try:
            norm = validate_scope_item(item)
        except TargetError as e:
            raise EngagementError(str(e)) from None
        with _LOCK:
            lst = self.excludes if exclude else self.includes
            if norm not in lst:
                lst.append(norm)
                self.save()
                self.audit("operator", "scope_exclude" if exclude else "scope_add", norm)
        return norm

    def remove_scope(self, item: str) -> bool:
        with _LOCK:
            removed = False
            for lst in (self.includes, self.excludes):
                for cand in (item, item.lower()):
                    if cand in lst:
                        lst.remove(cand)
                        removed = True
            if removed:
                self.save()
                self.audit("operator", "scope_remove", item)
            return removed

    def check(self, target: str) -> Decision:
        return self.scope.check(target)

    # ---------- findings ----------
    def add_finding(self, title, severity, description="", affected="", recommendation="", cve="", cvss="",
                    source="manual", evidence=None, status="open") -> Finding:
        severity = (severity or "").lower()
        if severity not in SEVERITIES:
            raise EngagementError(f"severity must be one of {', '.join(SEVERITIES)}")
        if status not in STATUSES:
            raise EngagementError(f"status must be one of {', '.join(STATUSES)}")
        if not (title or "").strip():
            raise EngagementError("title is required")
        with _LOCK:
            for f in self.findings:  # de-duplicate repeated tool runs
                if (f.title, f.affected, f.source) == (title, affected, source):
                    for ev in evidence or []:
                        if ev not in f.evidence:
                            f.evidence.append(ev)
                    f.updated = now()
                    self.save()
                    return f
            fid = "F-%03d" % (1 + max([int(f.id[2:]) for f in self.findings if f.id[2:].isdigit()] or [0]))
            f = Finding(fid, title.strip(), severity, description, affected, recommendation, cve, cvss, status,
                        source, list(evidence or []), now(), now())
            self.findings.append(f)
            self.save()
            self.audit(source, "finding_added", f"{fid} [{severity}] {title}")
            return f

    def get_finding(self, fid: str) -> Finding:
        for f in self.findings:
            if f.id == fid:
                return f
        raise EngagementError(f"Finding {fid} not found")

    def update_finding(self, fid: str, **changes) -> Finding:
        allowed = {"title", "severity", "description", "affected", "recommendation", "cve", "cvss", "status"}
        with _LOCK:
            f = self.get_finding(fid)
            for k, v in changes.items():
                if k not in allowed:
                    raise EngagementError(f"cannot change '{k}'")
                if k == "severity" and v not in SEVERITIES:
                    raise EngagementError("invalid severity")
                if k == "status" and v not in STATUSES:
                    raise EngagementError("invalid status")
                setattr(f, k, v)
            f.updated = now()
            self.save()
            self.audit("operator", "finding_updated", f"{fid} {sorted(changes)}")
            return f

    def delete_finding(self, fid: str) -> None:
        with _LOCK:
            f = self.get_finding(fid)
            self.findings.remove(f)
            self.save()
            self.audit("operator", "finding_deleted", f"{fid} {f.title}")

    def finding_counts(self) -> dict:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            if f.status != "false_positive":
                counts[f.severity] += 1
        return counts

    def sorted_findings(self) -> List[Finding]:
        order = {s: i for i, s in enumerate(SEVERITIES)}
        return sorted(self.findings, key=lambda f: (order[f.severity], f.id))

    # ---------- evidence ----------
    def save_evidence(self, name: str, data) -> Path:
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        path = self.evidence_dir / safe
        paths.write_private(path, data)
        return path

    # ---------- audit log (hash chained) ----------
    @property
    def audit_path(self) -> Path:
        return self.dir / "audit.jsonl"

    def audit(self, actor: str, action: str, detail: str = "") -> dict:
        with _LOCK:
            prev, seq = "0" * 64, 0
            if self.audit_path.exists():
                last = None
                with open(self.audit_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            last = line
                if last:
                    rec = json.loads(last)
                    prev, seq = rec["hash"], rec["seq"]
            rec = {"seq": seq + 1, "ts": now(), "actor": actor, "action": action, "detail": detail, "prev": prev}
            rec["hash"] = _chain_hash(rec)
            paths.secure_mkdir(self.dir)
            with open(self.audit_path, "a", encoding="utf-8", newline="\n") as f:
                f.write(json.dumps(rec, sort_keys=True) + "\n")
            paths.write_private(self.head_path, json.dumps({"seq": rec["seq"], "hash": rec["hash"]}))
            return rec

    @property
    def head_path(self) -> Path:
        return self.dir / "audit.head"

    def read_audit(self) -> List[dict]:
        if not self.audit_path.exists():
            return []
        with open(self.audit_path, "r", encoding="utf-8") as f:
            return [json.loads(l) for l in f if l.strip()]

    def verify_audit(self) -> tuple:
        """(ok, message). Detects edited, removed or reordered audit records."""
        prev, expected = "0" * 64, 1
        for rec in self.read_audit():
            body = {k: v for k, v in rec.items() if k != "hash"}
            if rec.get("seq") != expected:
                return False, f"sequence break at record {expected} (found {rec.get('seq')})"
            if rec.get("prev") != prev or _chain_hash(body) != rec.get("hash"):
                return False, f"hash mismatch at record {expected}"
            prev, expected = rec["hash"], expected + 1
        n = expected - 1
        try:
            head = json.loads(self.head_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return True, f"{n} records, chain intact (no head anchor found)"
        if (head.get("seq"), head.get("hash")) != (n, prev if n else "0" * 64):
            return False, f"log truncated or head anchor mismatch (anchor says {head.get('seq')} records, found {n})"
        return True, f"{n} records, chain intact, head anchored"


def _chain_hash(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode("utf-8")).hexdigest()


# ---------- helpers ----------
def list_engagements() -> List[str]:
    root = paths.engagements_dir()
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir() if (p / "engagement.json").exists())


def _current_file() -> Path:
    return paths.home() / "current"


def set_current(name: Optional[str]) -> None:
    if name is None:
        _current_file().unlink(missing_ok=True)
    else:
        check_name(name)
        paths.write_private(_current_file(), name)


def current_name() -> Optional[str]:
    try:
        return _current_file().read_text(encoding="utf-8").strip() or None
    except OSError:
        return None
