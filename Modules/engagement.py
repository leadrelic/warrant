"""
Engagement Module
Manages penetration testing engagements: client info, scope, findings,
audit trails, and evidence collection.

This is the cornerstone of professional red team workflow:
  - Define scope before touching anything
  - Every action is timestamped and attributed
  - Findings flow directly into the reporting pipeline
"""

import json
import logging
import ipaddress
import re
import socket
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field, asdict
from uuid import uuid4

from Modules.base_module import BaseModule, Colors

logger = logging.getLogger(__name__)

ENGAGEMENTS_ROOT = Path.home() / '.pentest_toolkit' / 'engagements'

# ─── Severity ordering for sorting/display ───────────────────────────────────

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
SEVERITY_COLORS = {
    'critical': Colors.FAIL,
    'high':     '\033[91m',   # bright red
    'medium':   Colors.WARNING,
    'low':      Colors.OKBLUE,
    'info':     Colors.OKCYAN,
}


# ─── Data Models ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single finding/vulnerability from the engagement."""
    id:             str
    title:          str
    severity:       str          # critical / high / medium / low / info
    description:    str
    affected:       str          # target/asset this affects
    recommendation: str
    evidence:       List[str]    # file paths or inline strings
    cve:            Optional[str]
    source:         str          # which module logged it
    timestamp:      str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'Finding':
        return cls(**d)

    def summary_line(self) -> str:
        sev_color = SEVERITY_COLORS.get(self.severity.lower(), '')
        return (
            f"{sev_color}[{self.severity.upper():<8}]{Colors.ENDC}  "
            f"{self.title:<50}  {self.affected}"
        )


@dataclass
class AuditEntry:
    timestamp: str
    module:    str
    command:   str
    detail:    str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> 'AuditEntry':
        return cls(**d)


@dataclass
class Engagement:
    """
    An authorized penetration testing engagement.

    Attributes:
        name        - Short engagement identifier  (e.g. "acme-q1-2026")
        client      - Client / target organisation name
        tester      - Tester name or team
        scope       - List of in-scope IP ranges, CIDRs, domains
        excluded    - List of explicitly excluded targets
        start_date  - ISO date string when engagement started
        end_date    - ISO date string (optional)
        description - Free-text description / rules of engagement
        findings    - List of Finding objects
        audit_log   - List of AuditEntry objects
        evidence_dir- Path where evidence files are stored
    """
    name:        str
    client:      str
    tester:      str
    scope:       List[str]
    excluded:    List[str]
    start_date:  str
    end_date:    str
    description: str
    findings:    List[Finding]   = field(default_factory=list)
    audit_log:   List[AuditEntry] = field(default_factory=list)

    # ── Persistence ──────────────────────────────────────────────────────

    @property
    def directory(self) -> Path:
        return ENGAGEMENTS_ROOT / self.name

    @property
    def evidence_dir(self) -> Path:
        d = self.directory / 'evidence'
        d.mkdir(parents=True, exist_ok=True)
        return d

    @property
    def json_path(self) -> Path:
        return self.directory / 'engagement.json'

    def save(self) -> bool:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            data = {
                'name':        self.name,
                'client':      self.client,
                'tester':      self.tester,
                'scope':       self.scope,
                'excluded':    self.excluded,
                'start_date':  self.start_date,
                'end_date':    self.end_date,
                'description': self.description,
                'findings':    [f.to_dict() for f in self.findings],
                'audit_log':   [a.to_dict() for a in self.audit_log],
            }
            with open(self.json_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save engagement: {e}")
            return False

    @classmethod
    def load(cls, name: str) -> Optional['Engagement']:
        path = ENGAGEMENTS_ROOT / name / 'engagement.json'
        if not path.exists():
            return None
        try:
            with open(path) as f:
                d = json.load(f)
            d['findings']  = [Finding.from_dict(x)   for x in d.get('findings', [])]
            d['audit_log'] = [AuditEntry.from_dict(x) for x in d.get('audit_log', [])]
            return cls(**d)
        except Exception as e:
            logger.error(f"Failed to load engagement {name}: {e}")
            return None

    # ── Scope checking ────────────────────────────────────────────────────

    def is_in_scope(self, target: str) -> bool:
        """
        Return True if the target is within scope and not excluded.
        Accepts: IP address, CIDR, hostname.
        """
        # Resolve hostname to IP first
        resolved_ip = None
        try:
            resolved_ip = ipaddress.ip_address(target)
        except ValueError:
            try:
                resolved_ip = ipaddress.ip_address(socket.gethostbyname(target))
            except (socket.gaierror, ValueError):
                pass  # Can't resolve — do string matching only

        # Check excluded list first
        for excl in self.excluded:
            if self._matches(target, excl, resolved_ip):
                return False

        # If scope is empty, everything is in scope
        if not self.scope:
            return True

        for item in self.scope:
            if self._matches(target, item, resolved_ip):
                return True

        return False

    @staticmethod
    def _matches(target: str, scope_item: str, resolved_ip=None) -> bool:
        """Check if target matches a scope item (CIDR, IP, or domain wildcard)."""
        # Exact string match
        if target.lower() == scope_item.lower():
            return True

        # CIDR range match
        try:
            network = ipaddress.ip_network(scope_item, strict=False)
            if resolved_ip and resolved_ip in network:
                return True
        except ValueError:
            pass

        # Domain wildcard  (*.example.com  or  example.com)
        if scope_item.startswith('*.'):
            parent = scope_item[2:]
            if target.lower().endswith('.' + parent.lower()) or target.lower() == parent.lower():
                return True
        elif target.lower().endswith('.' + scope_item.lower()):
            return True

        return False

    # ── Finding management ────────────────────────────────────────────────

    def add_finding(
        self,
        title:          str,
        severity:       str,
        description:    str,
        affected:       str       = '',
        recommendation: str       = '',
        evidence:       List[str] = None,
        cve:            str       = None,
        source:         str       = 'Manual',
    ) -> Finding:
        finding = Finding(
            id             = str(uuid4())[:8],
            title          = title,
            severity       = severity.lower(),
            description    = description,
            affected       = affected,
            recommendation = recommendation,
            evidence       = evidence or [],
            cve            = cve,
            source         = source,
            timestamp      = datetime.now().isoformat(),
        )
        self.findings.append(finding)
        self.save()
        logger.info(f"Finding added: [{severity}] {title} (affected: {affected})")
        return finding

    def findings_by_severity(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
        )

    # ── Audit trail ───────────────────────────────────────────────────────

    def audit(self, module: str, command: str, detail: str = '') -> None:
        entry = AuditEntry(
            timestamp = datetime.now().isoformat(),
            module    = module,
            command   = command,
            detail    = detail,
        )
        self.audit_log.append(entry)
        # Append to plain-text audit log too
        log_path = self.directory / 'audit.log'
        with open(log_path, 'a') as f:
            f.write(f"[{entry.timestamp}] [{module}] {command}  {detail}\n")

    # ── Stats ─────────────────────────────────────────────────────────────

    @property
    def finding_counts(self) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


# ─── Engagement Module (CLI) ─────────────────────────────────────────────────

class EngagementModule(BaseModule):
    """
    Interactive CLI for managing engagements.

    Commands:
        new          - Create a new engagement
        load         - Load an existing engagement
        info         - Show current engagement details
        scope        - Manage in-scope targets
        exclude      - Add exclusions
        check        - Check if a target is in scope
        finding      - Add a finding manually
        findings     - List all findings
        audit        - Show audit trail
        list         - List all saved engagements
        close        - Close/save the current engagement
    """

    MODULE_NAME   = "Engagement"
    MODULE_DESC   = "Manage red team engagements: scope, findings, audit trail"
    DEFAULT_CONFIG = {}

    prompt = '(engagement) '
    intro  = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
║              Engagement Management Module                      ║
║  Scope control • Finding tracker • Audit trail                 ║
╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}

Commands:
  new <name>              - Start a new engagement
  load <name>             - Load a saved engagement
  list                    - List all engagements
  info                    - Show current engagement summary
  scope add <target>      - Add a target to scope
  scope list              - List in-scope targets
  exclude <target>        - Add an exclusion
  check <target>          - Check if target is in scope
  finding                 - Add a finding interactively
  findings [severity]     - List findings (optionally filter by severity)
  audit [n]               - Show last n audit entries (default 20)
  close                   - Save and close current engagement

Type 'back' to return to main menu.
"""

    def __init__(self, engagement: Optional[Engagement] = None):
        super().__init__(engagement)

    # ── new ───────────────────────────────────────────────────────────────

    def do_new(self, arg: str) -> None:
        """
        Create a new engagement.

        Usage: new <engagement-name>

        You will be prompted for client, tester, scope, and description.
        """
        name = arg.strip()
        if not name:
            self._print_error("Usage: new <engagement-name>")
            return

        if not re.match(r'^[a-zA-Z0-9_\-]+$', name):
            self._print_error("Name must be alphanumeric (dashes/underscores OK).")
            return

        if (ENGAGEMENTS_ROOT / name).exists():
            self._print_warning(f"Engagement '{name}' already exists. Use 'load {name}' to open it.")
            return

        self._print_header(f"New Engagement: {name}")
        print(f"{Colors.DIM}Press Enter to leave a field blank.{Colors.ENDC}\n")

        client      = input(f"  {Colors.BOLD}Client / Organisation:{Colors.ENDC} ").strip()
        tester      = input(f"  {Colors.BOLD}Tester name / team:{Colors.ENDC}   ").strip()
        end_date    = input(f"  {Colors.BOLD}End date (YYYY-MM-DD):{Colors.ENDC} ").strip()
        description = input(f"  {Colors.BOLD}Description / notes:{Colors.ENDC}  ").strip()

        scope_raw   = input(
            f"  {Colors.BOLD}In-scope targets (comma-separated IPs/CIDRs/domains):{Colors.ENDC} "
        ).strip()
        scope = [s.strip() for s in scope_raw.split(',') if s.strip()]

        eng = Engagement(
            name        = name,
            client      = client or 'Unknown',
            tester      = tester or 'Unknown',
            scope       = scope,
            excluded    = [],
            start_date  = datetime.now().strftime('%Y-%m-%d'),
            end_date    = end_date,
            description = description,
        )

        if eng.save():
            self.engagement = eng
            self._print_success(f"Engagement '{name}' created and loaded.")
            self._print_info(f"Evidence directory: {eng.evidence_dir}")
            self._print_info(f"Scope: {scope if scope else 'unrestricted (no scope defined)'}")
        else:
            self._print_error("Failed to save engagement.")

    # ── load ──────────────────────────────────────────────────────────────

    def do_load(self, arg: str) -> None:
        """
        Load an existing engagement.

        Usage: load <engagement-name>
        """
        name = arg.strip()
        if not name:
            self._print_error("Usage: load <name>")
            return

        eng = Engagement.load(name)
        if eng is None:
            self._print_error(f"Engagement '{name}' not found.")
            self._print_info("Use 'list' to see available engagements.")
            return

        self.engagement = eng
        self._print_success(f"Loaded engagement: {eng.name}  [{eng.client}]")
        counts = eng.finding_counts
        self._print_info(
            f"Findings: "
            f"{Colors.FAIL}{counts.get('critical',0)}C{Colors.ENDC} "
            f"{Colors.WARNING}{counts.get('high',0)}H{Colors.ENDC} "
            f"{Colors.OKBLUE}{counts.get('medium',0)}M{Colors.ENDC} "
            f"{counts.get('low',0)}L  {counts.get('info',0)}I"
        )

    # ── list ──────────────────────────────────────────────────────────────

    def do_list(self, _arg: str) -> None:
        """List all saved engagements."""
        if not ENGAGEMENTS_ROOT.exists():
            self._print_info("No engagements found.")
            return

        names = [d.name for d in ENGAGEMENTS_ROOT.iterdir() if d.is_dir()]
        if not names:
            self._print_info("No engagements found.")
            return

        self._print_header("Saved Engagements")
        rows = []
        for n in sorted(names):
            eng = Engagement.load(n)
            if eng:
                counts  = eng.finding_counts
                f_total = sum(counts.values())
                active  = "◀ active" if (self.engagement and self.engagement.name == n) else ""
                rows.append([n, eng.client, eng.start_date, str(f_total), active])
        self._print_table(
            ['Name', 'Client', 'Started', 'Findings', ''],
            rows
        )
        print()

    # ── info ──────────────────────────────────────────────────────────────

    def do_info(self, _arg: str) -> None:
        """Show current engagement details."""
        eng = self.engagement
        if eng is None:
            self._print_warning("No engagement loaded. Use 'new' or 'load'.")
            return

        self._print_header(f"Engagement: {eng.name}")
        counts = eng.finding_counts
        print(f"  {'Client':<16} {eng.client}")
        print(f"  {'Tester':<16} {eng.tester}")
        print(f"  {'Started':<16} {eng.start_date}")
        print(f"  {'Ends':<16} {eng.end_date or 'Open-ended'}")
        print(f"  {'Description':<16} {eng.description or '—'}")
        print()
        print(f"  {'Scope':<16} {', '.join(eng.scope) if eng.scope else 'Unrestricted'}")
        print(f"  {'Excluded':<16} {', '.join(eng.excluded) if eng.excluded else 'None'}")
        print()
        print(f"  {'Findings':<16} "
              f"{Colors.FAIL}{counts.get('critical',0)} Critical{Colors.ENDC}  "
              f"{Colors.WARNING}{counts.get('high',0)} High{Colors.ENDC}  "
              f"{Colors.OKBLUE}{counts.get('medium',0)} Medium{Colors.ENDC}  "
              f"{counts.get('low',0)} Low  "
              f"{Colors.DIM}{counts.get('info',0)} Info{Colors.ENDC}")
        print(f"  {'Audit entries':<16} {len(eng.audit_log)}")
        print(f"  {'Evidence dir':<16} {eng.evidence_dir}")
        print()

    # ── scope ─────────────────────────────────────────────────────────────

    def do_scope(self, arg: str) -> None:
        """
        Manage in-scope targets.

        Usage:
            scope add <target>      - Add target to scope
            scope remove <target>   - Remove from scope
            scope list              - Show current scope
            scope clear             - Clear all scope entries
        """
        if self.engagement is None:
            self._print_warning("No engagement loaded.")
            return

        parts = arg.strip().split(maxsplit=1)
        sub   = parts[0].lower() if parts else 'list'
        val   = parts[1].strip() if len(parts) > 1 else ''

        if sub == 'list' or not sub:
            if self.engagement.scope:
                self._print_header("In-Scope Targets")
                for item in self.engagement.scope:
                    print(f"  {Colors.OKGREEN}+{Colors.ENDC}  {item}")
                print()
            else:
                self._print_warning("No scope defined — all targets are in scope.")

        elif sub == 'add':
            if not val:
                self._print_error("Usage: scope add <target>")
                return
            for t in [x.strip() for x in val.split(',') if x.strip()]:
                if t not in self.engagement.scope:
                    self.engagement.scope.append(t)
                    self._print_success(f"Added to scope: {t}")
                else:
                    self._print_info(f"Already in scope: {t}")
            self.engagement.save()

        elif sub == 'remove':
            if val in self.engagement.scope:
                self.engagement.scope.remove(val)
                self.engagement.save()
                self._print_success(f"Removed from scope: {val}")
            else:
                self._print_warning(f"'{val}' not found in scope.")

        elif sub == 'clear':
            self.engagement.scope = []
            self.engagement.save()
            self._print_success("Scope cleared.")

        else:
            self._print_error("Usage: scope [add|remove|list|clear] [target]")

    # ── exclude ───────────────────────────────────────────────────────────

    def do_exclude(self, arg: str) -> None:
        """
        Add an exclusion (target that must NOT be touched).

        Usage: exclude <target>
        """
        if self.engagement is None:
            self._print_warning("No engagement loaded.")
            return

        target = arg.strip()
        if not target:
            self._print_error("Usage: exclude <target>")
            return

        if target not in self.engagement.excluded:
            self.engagement.excluded.append(target)
            self.engagement.save()
            self._print_success(f"Exclusion added: {target}")
        else:
            self._print_info(f"Already excluded: {target}")

    # ── check ─────────────────────────────────────────────────────────────

    def do_check(self, arg: str) -> None:
        """
        Check whether a target is in scope.

        Usage: check <target>
        """
        if self.engagement is None:
            self._print_warning("No engagement loaded.")
            return

        target = arg.strip()
        if not target:
            self._print_error("Usage: check <target>")
            return

        if self.engagement.is_in_scope(target):
            self._print_success(f"'{target}' is IN SCOPE ✓")
        else:
            self._print_error(f"'{target}' is OUT OF SCOPE ✗")

    # ── finding (manual entry) ────────────────────────────────────────────

    def do_finding(self, _arg: str) -> None:
        """Add a finding interactively."""
        if self.engagement is None:
            self._print_warning("No engagement loaded.")
            return

        self._print_header("Add Finding")
        severities = ['critical', 'high', 'medium', 'low', 'info']

        title   = input(f"  {Colors.BOLD}Title:{Colors.ENDC}          ").strip()
        if not title:
            self._print_error("Title cannot be empty.")
            return

        print(f"  {Colors.BOLD}Severity options:{Colors.ENDC} " + " / ".join(severities))
        severity = input(f"  {Colors.BOLD}Severity:{Colors.ENDC}       ").strip().lower()
        if severity not in severities:
            self._print_error(f"Invalid severity. Choose from: {', '.join(severities)}")
            return

        affected   = input(f"  {Colors.BOLD}Affected target:{Colors.ENDC} ").strip()
        description = input(f"  {Colors.BOLD}Description:{Colors.ENDC}     ").strip()
        recommendation = input(f"  {Colors.BOLD}Recommendation:{Colors.ENDC}  ").strip()
        cve = input(f"  {Colors.BOLD}CVE (optional):{Colors.ENDC}  ").strip() or None

        f = self.engagement.add_finding(
            title=title,
            severity=severity,
            description=description,
            affected=affected,
            recommendation=recommendation,
            cve=cve,
            source='Manual',
        )
        self._print_success(f"Finding logged: [{f.id}] {f.title}")

    # ── findings ──────────────────────────────────────────────────────────

    def do_findings(self, arg: str) -> None:
        """
        List findings.

        Usage:
            findings                - All findings
            findings high           - Filter by severity
            findings critical       - Only critical findings
        """
        if self.engagement is None:
            self._print_warning("No engagement loaded.")
            return

        severity_filter = arg.strip().lower() or None
        findings = self.engagement.findings_by_severity()

        if severity_filter:
            findings = [f for f in findings if f.severity == severity_filter]

        if not findings:
            self._print_info("No findings recorded yet." if not severity_filter
                             else f"No {severity_filter} findings.")
            return

        self._print_header(f"Findings ({len(findings)} total)")
        for f in findings:
            print(f"  [{f.id}] {f.summary_line()}")
        print()

    # ── audit ─────────────────────────────────────────────────────────────

    def do_audit(self, arg: str) -> None:
        """
        Show the engagement audit trail.

        Usage: audit [n]    (default: last 20 entries)
        """
        if self.engagement is None:
            self._print_warning("No engagement loaded.")
            return

        try:
            n = int(arg.strip()) if arg.strip() else 20
        except ValueError:
            n = 20

        entries = self.engagement.audit_log[-n:]
        if not entries:
            self._print_info("Audit log is empty.")
            return

        self._print_header(f"Audit Trail (last {n})")
        for e in entries:
            ts = e.timestamp[:19].replace('T', ' ')
            print(f"  {Colors.DIM}{ts}{Colors.ENDC}  "
                  f"{Colors.OKBLUE}[{e.module:<12}]{Colors.ENDC}  "
                  f"{e.command}  {Colors.DIM}{e.detail}{Colors.ENDC}")
        print()

    # ── close ─────────────────────────────────────────────────────────────

    def do_close(self, _arg: str) -> None:
        """Save and close the current engagement."""
        if self.engagement is None:
            self._print_warning("No engagement loaded.")
            return

        if self.engagement.save():
            self._print_success(f"Engagement '{self.engagement.name}' saved.")
            self._print_info(f"Location: {self.engagement.json_path}")
            self.engagement = None
        else:
            self._print_error("Failed to save engagement.")


# ─── Convenience helpers ──────────────────────────────────────────────────────

def list_engagements() -> List[str]:
    """Return names of all saved engagements."""
    if not ENGAGEMENTS_ROOT.exists():
        return []
    return [d.name for d in ENGAGEMENTS_ROOT.iterdir() if d.is_dir()]


def load_engagement(name: str) -> Optional[Engagement]:
    """Load an engagement by name."""
    return Engagement.load(name)
