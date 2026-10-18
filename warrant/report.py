"""Report generation: HTML (self-contained, everything escaped), Markdown, JSON, CSV, optional PDF."""

import csv
import html
import io
import json
from datetime import datetime
from pathlib import Path

from . import __version__, paths
from .engagement import SEVERITIES, Engagement

SEV_COLORS = {"critical": "#8e1b1b", "high": "#c0392b", "medium": "#d9822b", "low": "#2f7fc1", "info": "#5d6d7e"}


def _tools_used(eng: Engagement):
    rows = {}
    for r in eng.read_audit():
        if r["action"] == "run_start":
            tool = r["detail"].split(" ", 1)[0]
            rows.setdefault(tool, {"runs": 0, "first": r["ts"]})["runs"] += 1
    return rows


def render_html(eng: Engagement) -> str:
    e = html.escape
    counts = eng.finding_counts()
    ok, msg = eng.verify_audit()
    total = max(sum(counts.values()), 1)
    bars = "".join(
        f'<div class="bar"><span class="lbl">{s.title()}</span><span class="fill" style="width:{counts[s] / total * 100:.0f}%;background:{SEV_COLORS[s]}"></span>'
        f'<span class="n">{counts[s]}</span></div>' for s in SEVERITIES)
    findings = []
    for f in eng.sorted_findings():
        meta = [("Affected", f.affected), ("CVE", f.cve), ("CVSS", f.cvss), ("Status", f.status.replace("_", " ")),
                ("Source", f.source), ("Evidence", ", ".join(f.evidence))]
        meta_html = "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in meta if v)
        findings.append(
            f'<section class="finding"><h3><span class="sev" style="background:{SEV_COLORS[f.severity]}">{e(f.severity.upper())}</span> '
            f"{e(f.id)} &mdash; {e(f.title)}</h3><dl>{meta_html}</dl>"
            + (f"<h4>Description</h4><pre>{e(f.description)}</pre>" if f.description else "")
            + (f"<h4>Recommendation</h4><p>{e(f.recommendation)}</p>" if f.recommendation else "") + "</section>")
    tools = "".join(f"<tr><td>{e(t)}</td><td>{d['runs']}</td><td>{e(d['first'])}</td></tr>" for t, d in sorted(_tools_used(eng).items()))
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{e(eng.name)} &mdash; Security Assessment Report</title>
<style>
body{{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem;color:#1c2833}}
h1{{margin-bottom:.2rem}} h2{{border-bottom:2px solid #d5d8dc;padding-bottom:.2rem;margin-top:2rem}}
table{{border-collapse:collapse;width:100%}} td,th{{border:1px solid #d5d8dc;padding:.35rem .6rem;text-align:left}}
.bar{{display:flex;align-items:center;gap:.6rem;margin:.2rem 0}} .lbl{{width:5.5rem}} .fill{{height:14px;min-width:2px;border-radius:3px}}
.sev{{color:#fff;padding:.1rem .5rem;border-radius:4px;font-size:.75rem}} .finding{{border:1px solid #d5d8dc;border-radius:6px;padding:.2rem 1rem 1rem;margin:1rem 0;break-inside:avoid}}
dl{{display:grid;grid-template-columns:7rem 1fr;gap:.2rem .8rem;margin:.5rem 0}} dt{{color:#5d6d7e}} dd{{margin:0;word-break:break-word}}
pre{{white-space:pre-wrap;background:#f4f6f7;padding:.6rem;border-radius:4px;word-break:break-word}} .muted{{color:#5d6d7e;font-size:.85rem}}
</style></head><body>
<h1>{e(eng.name)}</h1><p class="muted">Security assessment report &middot; generated {e(datetime.now().strftime('%Y-%m-%d %H:%M'))} by warrant {e(__version__)}</p>
<table><tr><th>Client</th><td>{e(eng.client)}</td><th>Tester</th><td>{e(eng.tester)}</td></tr>
<tr><th>Start</th><td>{e(eng.start_date)}</td><th>End</th><td>{e(eng.end_date or '-')}</td></tr></table>
{f'<p>{e(eng.description)}</p>' if eng.description else ''}
<h2>Executive summary</h2><p>{sum(counts.values())} findings recorded (false positives excluded).</p>{bars}
<h2>Scope</h2><table><tr><th>In scope</th><td>{e(', '.join(eng.includes) or 'none defined')}</td></tr>
<tr><th>Excluded</th><td>{e(', '.join(eng.excludes) or 'none')}</td></tr></table>
<h2>Findings</h2>{''.join(findings) or '<p>No findings recorded.</p>'}
<h2>Methodology and audit</h2><table><tr><th>Tool</th><th>Runs</th><th>First run (UTC)</th></tr>{tools or '<tr><td colspan=3>No tool runs recorded</td></tr>'}</table>
<p class="muted">Audit log integrity: {e('verified' if ok else 'FAILED')} &mdash; {e(msg)}.</p>
</body></html>"""


def render_markdown(eng: Engagement) -> str:
    counts = eng.finding_counts()
    L = [f"# {eng.name}: security assessment", "",
         f"- **Client:** {eng.client}", f"- **Tester:** {eng.tester}", f"- **Period:** {eng.start_date} to {eng.end_date or 'ongoing'}",
         f"- **In scope:** {', '.join(eng.includes) or 'none defined'}", f"- **Excluded:** {', '.join(eng.excludes) or 'none'}", "",
         "## Summary", "", "| Severity | Count |", "|---|---|"]
    L += [f"| {s.title()} | {counts[s]} |" for s in SEVERITIES]
    L += ["", "## Findings", ""]
    for f in eng.sorted_findings():
        L += [f"### {f.id} [{f.severity.upper()}] {f.title}", ""]
        for k, v in (("Affected", f.affected), ("CVE", f.cve), ("CVSS", f.cvss), ("Status", f.status), ("Source", f.source)):
            if v:
                L.append(f"- **{k}:** {v}")
        if f.description:
            L += ["", "```", f.description, "```"]
        if f.recommendation:
            L += ["", f"**Recommendation:** {f.recommendation}"]
        L.append("")
    ok, msg = eng.verify_audit()
    L += ["## Audit", "", f"Audit log: {'verified' if ok else 'FAILED'} ({msg})", ""]
    return "\n".join(L)


def render_csv(eng: Engagement) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["id", "severity", "status", "title", "affected", "cve", "cvss", "source", "description", "recommendation"])
    for f in eng.sorted_findings():
        # leading = + - @ would be interpreted as formulas by spreadsheet software
        row = [f.id, f.severity, f.status, f.title, f.affected, f.cve, f.cvss, f.source, f.description, f.recommendation]
        w.writerow([("'" + c) if isinstance(c, str) and c[:1] in ("=", "+", "-", "@") else c for c in row])
    return buf.getvalue()


def render_json(eng: Engagement) -> str:
    ok, msg = eng.verify_audit()
    return json.dumps({"engagement": eng.to_dict(), "audit_ok": ok, "audit": msg, "tools": _tools_used(eng)}, indent=2)


def write_report(eng: Engagement, fmt: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = eng.reports_dir / f"{eng.name}_{stamp}.{'html' if fmt == 'pdf' else fmt}"
    if fmt == "pdf":
        try:
            from weasyprint import HTML
        except ImportError:
            raise RuntimeError("PDF output needs weasyprint: pip install weasyprint") from None
        out = out.with_suffix(".pdf")
        paths.write_private(out, HTML(string=render_html(eng)).write_pdf())
    elif fmt == "html":
        paths.write_private(out, render_html(eng))
    elif fmt in ("md", "markdown"):
        out = out.with_suffix(".md")
        paths.write_private(out, render_markdown(eng))
    elif fmt == "csv":
        paths.write_private(out, render_csv(eng))
    elif fmt == "json":
        paths.write_private(out, render_json(eng))
    else:
        raise ValueError(f"unknown report format '{fmt}' (html, md, json, csv, pdf)")
    eng.audit("operator", "report_generated", out.name)
    return out
