"""Command line interface. `warrant shell` runs the same commands interactively."""

import argparse
import shlex
import sys

from . import __version__
from .engagement import (SEVERITIES, STATUSES, Engagement, EngagementError, current_name, list_engagements,
                         set_current)
from .report import write_report
from .runner import NoEngagement, ScopeViolation, ToolMissing, ToolRunner
from .tools import REGISTRY
from .validate import ValidationError

SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "34", "info": "90"}


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else str(text)


def get_engagement(args, required=True):
    name = getattr(args, "engagement", None) or current_name()
    if not name:
        if required:
            raise EngagementError("No engagement selected. Use `warrant new NAME` or `warrant use NAME` (or -e NAME).")
        return None
    return Engagement.load(name)


# ---------- command handlers ----------
def cmd_new(a):
    eng = Engagement.create(a.name, client=a.client, tester=a.tester, description=a.description, end_date=a.end,
                            start_date=a.start, includes=[], excludes=[])
    for s in a.scope or []:
        eng.add_scope(s)
    for s in a.exclude or []:
        eng.add_scope(s, exclude=True)
    set_current(eng.name)
    print(f"Created engagement '{eng.name}' and made it current.")
    if not eng.includes:
        print(c("No scope defined yet: runs are blocked until you add some (warrant scope add ...).", "33"))
    return 0


def cmd_list(a):
    cur = current_name()
    for n in list_engagements():
        e = Engagement.load(n)
        print(f"{'*' if n == cur else ' '} {n:<28} {e.client:<24} {sum(e.finding_counts().values())} findings")
    return 0


def cmd_use(a):
    Engagement.load(a.name)
    set_current(a.name)
    print(f"Current engagement: {a.name}")
    return 0


def cmd_show(a):
    e = get_engagement(a)
    print(f"{c(e.name, '1')}  client={e.client}  tester={e.tester}  {e.start_date} -> {e.end_date or 'ongoing'}")
    problem = e.window_error()
    if problem:
        print(c(f"Runs are blocked: {problem}", "1;31"))
    print("In scope:  " + (", ".join(e.includes) or c("(none)", "33")))
    print("Excluded:  " + (", ".join(e.excludes) or "(none)"))
    counts = e.finding_counts()
    print("Findings:  " + "  ".join(f"{s}={counts[s]}" for s in SEVERITIES))
    ok, msg = e.verify_audit()
    print("Audit log: " + (c(msg, "32") if ok else c("TAMPERED: " + msg, "1;31")))
    return 0


def cmd_scope(a):
    e = get_engagement(a)
    if a.action in ("add", "exclude"):
        for item in a.items:
            print(f"{'Excluded' if a.action == 'exclude' else 'Added'}: {e.add_scope(item, exclude=a.action == 'exclude')}")
    elif a.action == "rm":
        for item in a.items:
            print(("Removed " if e.remove_scope(item) else "Not found: ") + item)
    elif a.action == "check":
        rc = 0
        for item in a.items:
            d = e.check(item)
            print(f"{c('IN ', '32') if d.allowed else c('OUT', '31')}  {item}  ({d.reason})" + (f"  resolves: {', '.join(d.resolved)}" if d.resolved else ""))
            for w in d.warnings:
                print(c(f"     ! {w}", "33"))
            rc |= 0 if d.allowed else 3
        return rc
    else:
        print("In scope:\n  " + "\n  ".join(e.includes or ["(none)"]))
        print("Excluded:\n  " + "\n  ".join(e.excludes or ["(none)"]))
    return 0


def cmd_tools(a):
    if a.tool:
        t = REGISTRY.get(a.tool)
        if not t:
            print(f"Unknown tool '{a.tool}'")
            return 2
        print(f"{c(t.id, '1')} - {t.description}")
        if not t.available():
            print(c(f"  not installed: {t.install}", "33"))
        for p in t.params:
            extra = f" choices={p.choices}" if p.choices else ""
            extra += f" default={p.default}" if p.default not in (None, "") else ""
            print(f"  {p.name:<14} {p.kind:<7} {'required' if p.required and p.default is None else 'optional'}{extra}  {p.label}")
        return 0
    cat = None
    for t in sorted(REGISTRY.values(), key=lambda t: (t.category, t.id)):
        if t.category != cat:
            cat = t.category
            print("\n" + c(cat, "1"))
        mark = c("✓", "32") if t.available() else c("✗", "31")
        print(f"  {mark} {t.id:<15} {t.description}")
    return 0


def cmd_run(a):
    spec = REGISTRY.get(a.tool)
    if not spec:
        print(f"Unknown tool '{a.tool}'. See `warrant tools`.")
        return 2
    params, positional = {}, [x for x in a.args if "=" not in x]
    for item in a.args:
        if "=" in item:
            k, v = item.split("=", 1)
            params[k] = v
    if positional:
        if len(positional) > 1:
            print("Only the first parameter can be positional; use key=value for the rest.")
            return 2
        params[spec.params[0].name] = positional[0]
    eng = get_engagement(a, required=not a.no_engagement)
    if eng is None:
        print(c("WARNING: running without an engagement: no scope check, no audit log, no findings.", "1;33"))
    runner = ToolRunner(eng, REGISTRY, unscoped=a.no_engagement)
    print(c(f"[{spec.id}]", "36"))
    res = runner.run(spec.id, params, on_line=print, record_findings=not a.no_findings)
    print()
    print(f"{res.status.upper()} in {res.duration:.1f}s" + (f" (exit {res.returncode})" if res.returncode is not None else ""))
    for f in res.findings:
        print(f"  + {c(f.severity.upper(), SEV_COLOR[f.severity])} {f.id} {f.title}")
    if res.output_file:
        print(f"Output saved: {res.output_file}")
    return 0 if res.status == "done" else 1


def cmd_finding(a):
    e = get_engagement(a)
    if a.action == "add":
        f = e.add_finding(a.title, a.severity, a.description, a.affected, a.recommendation, a.cve or "", a.cvss or "")
        print(f"Added {f.id}")
    elif a.action == "list":
        for f in e.sorted_findings():
            print(f"{f.id}  {c(f.severity.upper().ljust(8), SEV_COLOR[f.severity])} {f.status:<14} {f.title}")
    elif a.action == "set":
        changes = dict(x.split("=", 1) for x in a.changes)
        f = e.update_finding(a.id, **changes)
        print(f"Updated {f.id}")
    elif a.action == "rm":
        e.delete_finding(a.id)
        print(f"Deleted {a.id}")
    return 0


def cmd_audit(a):
    e = get_engagement(a)
    ok, msg = e.verify_audit()
    if not a.verify:
        for r in e.read_audit()[-a.tail:]:
            print(f"{r['seq']:>4} {r['ts']} {r['actor']:<9} {r['action']:<16} {r['detail'][:160]}")
    print(("Chain OK: " if ok else "CHAIN BROKEN: ") + msg)
    return 0 if ok else 1


def cmd_report(a):
    e = get_engagement(a)
    for fmt in a.format.split(","):
        print(f"Wrote {write_report(e, fmt.strip())}")
    return 0


def cmd_serve(a):
    from .web.server import serve
    return serve(a.host, a.port, a.no_browser, a.allow_remote)


def cmd_shell(a):
    print(f"warrant {__version__} shell. `help` lists commands, `exit` quits.")
    while True:
        try:
            line = input(f"warrant[{current_name() or '-'}]> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if line in ("exit", "quit"):
            return 0
        if not line:
            continue
        if line == "help":
            line = "--help"
        try:
            main(shlex.split(line))
        except SystemExit:
            pass
        except ValueError as e:
            print(f"parse error: {e}")


# ---------- parser ----------
def build_parser():
    p = argparse.ArgumentParser(prog="warrant", description="Scope-enforcing pentest toolkit.")
    p.add_argument("--version", action="version", version=f"warrant {__version__}")
    p.add_argument("-e", "--engagement", help="engagement name (default: current)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("new", help="create an engagement")
    s.add_argument("name")
    s.add_argument("--client", default="")
    s.add_argument("--tester", default="")
    s.add_argument("--description", default="")
    s.add_argument("--start", default="", help="first authorized day, YYYY-MM-DD (default: today)")
    s.add_argument("--end", default="", help="last authorized day, YYYY-MM-DD; runs are blocked after it")
    s.add_argument("--scope", action="append", help="in-scope IP/CIDR/range/domain (repeatable)")
    s.add_argument("--exclude", action="append", help="excluded target (repeatable)")
    s.set_defaults(fn=cmd_new)

    sub.add_parser("list", help="list engagements").set_defaults(fn=cmd_list)
    s = sub.add_parser("use", help="select the current engagement")
    s.add_argument("name")
    s.set_defaults(fn=cmd_use)
    sub.add_parser("show", help="engagement summary").set_defaults(fn=cmd_show)

    s = sub.add_parser("scope", help="manage scope")
    s.add_argument("action", choices=["add", "exclude", "rm", "check", "list"])
    s.add_argument("items", nargs="*")
    s.set_defaults(fn=cmd_scope)

    s = sub.add_parser("tools", help="list tools or show one tool's parameters")
    s.add_argument("tool", nargs="?")
    s.set_defaults(fn=cmd_tools)

    s = sub.add_parser("run", help="run a tool: warrant run nmap 10.0.0.5 profile=quick")
    s.add_argument("tool")
    s.add_argument("args", nargs="*", help="first value is the primary target; others as key=value")
    s.add_argument("--no-findings", action="store_true", help="don't record findings")
    s.add_argument("--no-engagement", action="store_true", help="run without scope/audit (explicit opt-out)")
    s.set_defaults(fn=cmd_run)

    s = sub.add_parser("finding", help="manage findings")
    fs = s.add_subparsers(dest="action", required=True)
    f = fs.add_parser("add")
    f.add_argument("--title", required=True)
    f.add_argument("--severity", required=True, choices=SEVERITIES)
    f.add_argument("--description", default="")
    f.add_argument("--affected", default="")
    f.add_argument("--recommendation", default="")
    f.add_argument("--cve")
    f.add_argument("--cvss")
    fs.add_parser("list")
    f = fs.add_parser("set", help="finding set F-001 status=confirmed severity=high")
    f.add_argument("id")
    f.add_argument("changes", nargs="+")
    f = fs.add_parser("rm")
    f.add_argument("id")
    s.set_defaults(fn=cmd_finding)

    s = sub.add_parser("audit", help="show or verify the audit log")
    s.add_argument("--verify", action="store_true")
    s.add_argument("--tail", type=int, default=30)
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("report", help="generate reports")
    s.add_argument("--format", default="html", help="comma list of html,md,json,csv,pdf")
    s.set_defaults(fn=cmd_report)

    s = sub.add_parser("serve", help="start the web GUI")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--no-browser", action="store_true")
    s.add_argument("--allow-remote", action="store_true", help="allow binding to a non-loopback address")
    s.set_defaults(fn=cmd_serve)

    sub.add_parser("shell", help="interactive shell").set_defaults(fn=cmd_shell)
    return p


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, OSError):
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args) or 0
    except ScopeViolation as e:
        print(c("BLOCKED: out of scope", "1;31"))
        for d in e.decisions:
            print(f"  {d.target}: {d.reason}")
        return 3
    except (EngagementError, ValidationError, NoEngagement, ToolMissing) as e:
        print(c(f"Error: {e}", "31"))
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
