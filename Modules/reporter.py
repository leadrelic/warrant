"""
Reporter Module
Generates professional HTML/PDF penetration testing reports from engagement data.

Output formats:
  - HTML  (always available, no deps)
  - PDF   (requires weasyprint: pip install weasyprint)
  - JSON  (machine-readable findings export)
  - CSV   (findings spreadsheet export)
"""

import json
import csv
import io
import logging
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional

from Modules.base_module import BaseModule, Colors
from Modules.engagement import Engagement, SEVERITY_COLORS, SEVERITY_ORDER

logger = logging.getLogger(__name__)

REPORTS_DIR = Path.home() / '.pentest_toolkit' / 'reports'


# ─── HTML template ───────────────────────────────────────────────────────────

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  :root {{
    --critical: #c0392b; --high: #e74c3c; --medium: #e67e22;
    --low: #3498db;      --info:  #27ae60;
    --bg: #0d1117;       --surface: #161b22; --surface2: #21262d;
    --border: #30363d;   --text: #c9d1d9;   --text-dim: #8b949e;
    --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    padding: 40px 60px; max-width: 1100px; margin: 0 auto;
  }}
  h1 {{ font-size: 2rem; color: var(--accent); margin-bottom: 4px; }}
  h2 {{ font-size: 1.25rem; color: var(--text); margin: 32px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
  h3 {{ font-size: 1rem; color: var(--text); }}
  .meta {{ color: var(--text-dim); font-size: 0.85rem; margin-bottom: 32px; }}
  .meta span {{ margin-right: 24px; }}

  /* Summary boxes */
  .summary-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin: 16px 0 32px; }}
  .sev-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .sev-card .count {{ font-size: 2rem; font-weight: 700; }}
  .sev-card .label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 1px; }}
  .sev-critical .count {{ color: var(--critical); }}
  .sev-high     .count {{ color: var(--high);     }}
  .sev-medium   .count {{ color: var(--medium);   }}
  .sev-low      .count {{ color: var(--low);      }}
  .sev-info     .count {{ color: var(--info);     }}

  /* Findings table */
  .findings-table {{ width: 100%; border-collapse: collapse; margin: 12px 0; }}
  .findings-table th {{ background: var(--surface2); color: var(--text-dim); font-size: 0.75rem;
                         text-transform: uppercase; letter-spacing: 0.8px; padding: 10px 12px; text-align: left; }}
  .findings-table td {{ padding: 10px 12px; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  .findings-table tr:hover td {{ background: var(--surface); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem;
             font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }}
  .badge-critical {{ background: #c0392b22; color: var(--critical); border: 1px solid var(--critical); }}
  .badge-high     {{ background: #e74c3c22; color: var(--high);     border: 1px solid var(--high);     }}
  .badge-medium   {{ background: #e67e2222; color: var(--medium);   border: 1px solid var(--medium);   }}
  .badge-low      {{ background: #3498db22; color: var(--low);      border: 1px solid var(--low);      }}
  .badge-info     {{ background: #27ae6022; color: var(--info);     border: 1px solid var(--info);     }}

  /* Detail cards */
  .finding-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
                   margin: 12px 0; padding: 20px; page-break-inside: avoid; }}
  .finding-card .card-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }}
  .finding-card .card-id {{ color: var(--text-dim); font-size: 0.75rem; font-family: monospace; }}
  .card-section {{ margin-top: 12px; }}
  .card-section .section-label {{ font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.8px;
                                   color: var(--text-dim); margin-bottom: 4px; }}
  .card-section p {{ font-size: 0.9rem; }}
  .cve-badge {{ background: #8b949e22; color: #8b949e; border: 1px solid #8b949e;
                padding: 2px 7px; border-radius: 4px; font-size: 0.72rem; font-family: monospace; }}

  /* Scope & info table */
  .info-table {{ width: 100%; border-collapse: collapse; }}
  .info-table td {{ padding: 7px 0; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
  .info-table td:first-child {{ color: var(--text-dim); width: 160px; }}

  /* Footer */
  footer {{ margin-top: 60px; padding-top: 16px; border-top: 1px solid var(--border);
             color: var(--text-dim); font-size: 0.8rem; display: flex; justify-content: space-between; }}

  @media print {{
    body {{ background: white; color: black; padding: 20px; }}
    .finding-card {{ border: 1px solid #ccc; }}
    h1, h2 {{ color: black; }}
  }}
</style>
</head>
<body>

<h1>🔒 Penetration Test Report</h1>
<div class="meta">
  <span><strong>Engagement:</strong> {engagement_name}</span>
  <span><strong>Client:</strong> {client}</span>
  <span><strong>Tester:</strong> {tester}</span>
  <span><strong>Generated:</strong> {generated_at}</span>
</div>

<h2>Executive Summary</h2>
<table class="info-table">
  <tr><td>Client</td><td>{client}</td></tr>
  <tr><td>Engagement</td><td>{engagement_name}</td></tr>
  <tr><td>Test period</td><td>{start_date} → {end_date}</td></tr>
  <tr><td>Tester</td><td>{tester}</td></tr>
  <tr><td>Scope</td><td>{scope}</td></tr>
  <tr><td>Description</td><td>{description}</td></tr>
</table>

<h2>Risk Summary</h2>
<div class="summary-grid">
  <div class="sev-card sev-critical"><div class="count">{count_critical}</div><div class="label">Critical</div></div>
  <div class="sev-card sev-high">    <div class="count">{count_high}</div>    <div class="label">High</div></div>
  <div class="sev-card sev-medium">  <div class="count">{count_medium}</div>  <div class="label">Medium</div></div>
  <div class="sev-card sev-low">     <div class="count">{count_low}</div>     <div class="label">Low</div></div>
  <div class="sev-card sev-info">    <div class="count">{count_info}</div>    <div class="label">Info</div></div>
</div>

<h2>Findings Overview</h2>
<table class="findings-table">
  <thead>
    <tr><th>#</th><th>Severity</th><th>Title</th><th>Affected</th><th>CVE</th><th>Source</th></tr>
  </thead>
  <tbody>
    {findings_table_rows}
  </tbody>
</table>

<h2>Detailed Findings</h2>
{finding_cards}

<h2>Scope & Methodology</h2>
<table class="info-table">
  <tr><td>In-scope targets</td><td>{scope}</td></tr>
  <tr><td>Exclusions</td><td>{excluded}</td></tr>
  <tr><td>Start date</td><td>{start_date}</td></tr>
  <tr><td>End date</td><td>{end_date}</td></tr>
  <tr><td>Total audit entries</td><td>{audit_count}</td></tr>
</table>

<footer>
  <span>Generated by Pentesters-ToolKit v3.0 — {generated_at}</span>
  <span>CONFIDENTIAL — Authorized Security Testing Only</span>
</footer>
</body>
</html>
"""

FINDING_CARD_TEMPLATE = """
<div class="finding-card">
  <div class="card-header">
    <span class="badge badge-{severity}">{severity_upper}</span>
    <h3>{title}</h3>
    <span class="card-id">#{id}</span>
    {cve_badge}
  </div>
  <div class="card-section">
    <div class="section-label">Affected Asset</div>
    <p>{affected}</p>
  </div>
  <div class="card-section">
    <div class="section-label">Description</div>
    <p>{description}</p>
  </div>
  <div class="card-section">
    <div class="section-label">Recommendation</div>
    <p>{recommendation}</p>
  </div>
  <div class="card-section">
    <div class="section-label">Source / Timestamp</div>
    <p>{source} — {timestamp}</p>
  </div>
  {evidence_section}
</div>
"""

TABLE_ROW_TEMPLATE = """
<tr>
  <td>{idx}</td>
  <td><span class="badge badge-{severity}">{severity_upper}</span></td>
  <td>{title}</td>
  <td>{affected}</td>
  <td>{cve}</td>
  <td>{source}</td>
</tr>
"""


# ─── Report generator ─────────────────────────────────────────────────────────

class ReportGenerator:
    """Generates reports from an Engagement object."""

    def __init__(self, engagement: Engagement):
        self.engagement = engagement
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def _build_html(self) -> str:
        eng    = self.engagement
        counts = eng.finding_counts
        now    = datetime.now().strftime('%Y-%m-%d %H:%M')

        # Table rows
        table_rows = ''
        for i, f in enumerate(eng.findings_by_severity(), 1):
            table_rows += TABLE_ROW_TEMPLATE.format(
                idx          = i,
                severity     = f.severity,
                severity_upper = f.severity.upper(),
                title        = self._esc(f.title),
                affected     = self._esc(f.affected),
                cve          = f.cve or '—',
                source       = self._esc(f.source),
            )

        # Detail cards
        cards = ''
        for f in eng.findings_by_severity():
            cve_badge = (
                f'<span class="cve-badge">{f.cve}</span>' if f.cve else ''
            )
            evidence_html = ''
            if f.evidence:
                items = ''.join(
                    f'<li style="font-family:monospace;font-size:0.85rem">{self._esc(e)}</li>'
                    for e in f.evidence
                )
                evidence_html = (
                    f'<div class="card-section">'
                    f'<div class="section-label">Evidence</div>'
                    f'<ul style="padding-left:18px;margin-top:4px">{items}</ul>'
                    f'</div>'
                )
            cards += FINDING_CARD_TEMPLATE.format(
                id             = f.id,
                severity       = f.severity,
                severity_upper = f.severity.upper(),
                title          = self._esc(f.title),
                affected       = self._esc(f.affected),
                description    = self._esc(f.description).replace('\n', '<br>'),
                recommendation = self._esc(f.recommendation).replace('\n', '<br>'),
                source         = self._esc(f.source),
                timestamp      = f.timestamp[:19].replace('T', ' '),
                cve_badge      = cve_badge,
                evidence_section = evidence_html,
            )

        return HTML_TEMPLATE.format(
            title           = f"Pentest Report — {eng.name}",
            engagement_name = self._esc(eng.name),
            client          = self._esc(eng.client),
            tester          = self._esc(eng.tester),
            generated_at    = now,
            start_date      = eng.start_date,
            end_date        = eng.end_date or 'Ongoing',
            scope           = self._esc(', '.join(eng.scope) if eng.scope else 'Unrestricted'),
            excluded        = self._esc(', '.join(eng.excluded) if eng.excluded else 'None'),
            description     = self._esc(eng.description),
            count_critical  = counts.get('critical', 0),
            count_high      = counts.get('high', 0),
            count_medium    = counts.get('medium', 0),
            count_low       = counts.get('low', 0),
            count_info      = counts.get('info', 0),
            findings_table_rows = table_rows,
            finding_cards   = cards if cards else '<p style="color:#8b949e">No findings recorded.</p>',
            audit_count     = len(eng.audit_log),
        )

    @staticmethod
    def _esc(text: str) -> str:
        """Basic HTML escaping."""
        return (text or '')                 \
            .replace('&', '&amp;')          \
            .replace('<', '&lt;')           \
            .replace('>', '&gt;')           \
            .replace('"', '&quot;')

    def generate_html(self, output_path: Optional[Path] = None) -> Path:
        """Write HTML report and return its path."""
        if output_path is None:
            ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = REPORTS_DIR / f'report_{self.engagement.name}_{ts}.html'

        html = self._build_html()
        output_path.write_text(html, encoding='utf-8')
        logger.info(f"HTML report written to {output_path}")
        return output_path

    def generate_pdf(self, output_path: Optional[Path] = None) -> Optional[Path]:
        """
        Convert HTML report to PDF via weasyprint (if installed).
        Falls back gracefully and returns None if unavailable.
        """
        html_path = self.generate_html()   # Always generate HTML first

        if output_path is None:
            output_path = html_path.with_suffix('.pdf')

        try:
            import weasyprint  # type: ignore
            weasyprint.HTML(filename=str(html_path)).write_pdf(str(output_path))
            logger.info(f"PDF report written to {output_path}")
            return output_path
        except ImportError:
            logger.warning("weasyprint not installed — PDF generation unavailable.")
            return None
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None

    def generate_json(self, output_path: Optional[Path] = None) -> Path:
        """Export findings as JSON."""
        if output_path is None:
            ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = REPORTS_DIR / f'findings_{self.engagement.name}_{ts}.json'

        data = {
            'engagement':  self.engagement.name,
            'client':      self.engagement.client,
            'tester':      self.engagement.tester,
            'generated':   datetime.now().isoformat(),
            'findings':    [f.to_dict() for f in self.engagement.findings_by_severity()],
            'summary':     self.engagement.finding_counts,
        }
        output_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        return output_path

    def generate_csv(self, output_path: Optional[Path] = None) -> Path:
        """Export findings as CSV."""
        if output_path is None:
            ts   = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = REPORTS_DIR / f'findings_{self.engagement.name}_{ts}.csv'

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'id', 'severity', 'title', 'affected', 'description',
                'recommendation', 'cve', 'source', 'timestamp'
            ])
            writer.writeheader()
            for finding in self.engagement.findings_by_severity():
                writer.writerow({
                    'id':             finding.id,
                    'severity':       finding.severity,
                    'title':          finding.title,
                    'affected':       finding.affected,
                    'description':    finding.description,
                    'recommendation': finding.recommendation,
                    'cve':            finding.cve or '',
                    'source':         finding.source,
                    'timestamp':      finding.timestamp[:19],
                })
        return output_path


# ─── Reporter CLI module ──────────────────────────────────────────────────────

class ReporterModule(BaseModule):
    """
    Interactive report generation module.

    Commands:
        html [path]     - Generate HTML report
        pdf  [path]     - Generate PDF report (requires weasyprint)
        json [path]     - Export findings as JSON
        csv  [path]     - Export findings as CSV
        open            - Open latest HTML report in browser
        list            - List generated reports
    """

    MODULE_NAME    = "Reporter"
    MODULE_DESC    = "Generate HTML/PDF/JSON/CSV reports from engagement findings"
    DEFAULT_CONFIG: dict = {}

    prompt = '(reporter) '
    intro  = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
║                   Report Generator                             ║
║  HTML • PDF • JSON • CSV                                       ║
╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}

Commands:
  html [path]     - Generate HTML report
  pdf  [path]     - Generate PDF report (requires: pip install weasyprint)
  json [path]     - Export findings as JSON
  csv  [path]     - Export findings as CSV
  open            - Open latest HTML report in browser
  list            - List generated reports

Type 'back' to return to main menu.
"""

    # ── html ──────────────────────────────────────────────────────────────

    def do_html(self, arg: str) -> None:
        """Generate HTML report. Usage: html [output_path]"""
        if not self._check_engagement():
            return
        path = Path(arg.strip()) if arg.strip() else None
        gen  = ReportGenerator(self.engagement)
        out  = gen.generate_html(path)
        self._print_success(f"HTML report: {out}")
        self._audit('html', str(out))

    # ── pdf ───────────────────────────────────────────────────────────────

    def do_pdf(self, arg: str) -> None:
        """Generate PDF report. Usage: pdf [output_path]  (requires weasyprint)"""
        if not self._check_engagement():
            return
        path = Path(arg.strip()) if arg.strip() else None
        gen  = ReportGenerator(self.engagement)
        self._print_info("Generating PDF (HTML will be saved first)...")
        out  = gen.generate_pdf(path)
        if out:
            self._print_success(f"PDF report: {out}")
            self._audit('pdf', str(out))
        else:
            self._print_warning(
                "PDF generation failed or weasyprint is not installed.\n"
                "  Install it with:  pip install weasyprint\n"
                "  HTML report was still saved."
            )

    # ── json ──────────────────────────────────────────────────────────────

    def do_json(self, arg: str) -> None:
        """Export findings as JSON. Usage: json [output_path]"""
        if not self._check_engagement():
            return
        path = Path(arg.strip()) if arg.strip() else None
        gen  = ReportGenerator(self.engagement)
        out  = gen.generate_json(path)
        self._print_success(f"JSON export: {out}")

    # ── csv ───────────────────────────────────────────────────────────────

    def do_csv(self, arg: str) -> None:
        """Export findings as CSV. Usage: csv [output_path]"""
        if not self._check_engagement():
            return
        path = Path(arg.strip()) if arg.strip() else None
        gen  = ReportGenerator(self.engagement)
        out  = gen.generate_csv(path)
        self._print_success(f"CSV export: {out}")

    # ── open ──────────────────────────────────────────────────────────────

    def do_open(self, _arg: str) -> None:
        """Open the latest HTML report in a browser."""
        reports = sorted(REPORTS_DIR.glob('report_*.html'))
        if not reports:
            self._print_warning("No HTML reports found. Run 'html' first.")
            return
        latest = reports[-1]
        try:
            import webbrowser
            webbrowser.open(f'file://{latest}')
            self._print_success(f"Opened: {latest}")
        except Exception as e:
            self._print_info(f"Report path: {latest}")

    # ── list ──────────────────────────────────────────────────────────────

    def do_list(self, _arg: str) -> None:
        """List all generated reports."""
        all_reports = sorted(REPORTS_DIR.iterdir()) if REPORTS_DIR.exists() else []
        if not all_reports:
            self._print_info("No reports generated yet.")
            return
        self._print_header("Generated Reports")
        for r in all_reports:
            size = r.stat().st_size
            ts   = datetime.fromtimestamp(r.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
            print(f"  {Colors.OKCYAN}{r.name:<55}{Colors.ENDC}  {size:>8,} B  {ts}")
        print()

    # ── helpers ───────────────────────────────────────────────────────────

    def _check_engagement(self) -> bool:
        if self.engagement is None:
            self._print_warning(
                "No engagement loaded. Load one from the main menu:\n"
                "  engagement → load <name>"
            )
            return False
        return True
