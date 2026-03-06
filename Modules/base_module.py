"""
Base Module
Shared base class for all toolkit modules — eliminates copy-paste boilerplate,
provides shared config handling, logging, printing, scope validation, and
engagement-awareness.
"""

import cmd
import json
import logging
import re
import ipaddress
import socket
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any


# ─── ANSI Colors ────────────────────────────────────────────────────────────

class Colors:
    HEADER    = '\033[95m'
    OKBLUE    = '\033[94m'
    OKCYAN    = '\033[96m'
    OKGREEN   = '\033[92m'
    WARNING   = '\033[93m'
    FAIL      = '\033[91m'
    ENDC      = '\033[0m'
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM       = '\033[2m'

    @staticmethod
    def strip(text: str) -> str:
        """Remove ANSI codes from a string."""
        return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', text)


# ─── Module-level shared config defaults ─────────────────────────────────────

MODULE_RESULTS_ROOT = Path.home() / '.pentest_toolkit'


# ─── BaseModule ──────────────────────────────────────────────────────────────

class BaseModule(cmd.Cmd):
    """
    Abstract base for all toolkit modules.

    Subclasses should define:
        MODULE_NAME     - str, e.g. "Nmap"
        MODULE_DESC     - str, one-liner description
        DEFAULT_CONFIG  - dict of default config keys/values

    The base class provides:
        • Coloured print helpers (_print_success / _print_error / etc.)
        • Shared do_config / do_back / do_exit / emptyline / default
        • results_dir (Path) under ~/.pentest_toolkit/<module_slug>/
        • Engagement awareness via self.engagement (injected by toolkit)
        • Scope validation helpers
        • Audit logging (every command goes to the session audit trail)
    """

    MODULE_NAME    = "Module"
    MODULE_DESC    = ""
    DEFAULT_CONFIG: Dict[str, Any] = {}

    # ── Lifecycle ──────────────────────────────────────────────────────────

    def __init__(self, engagement=None):
        super().__init__()
        self.logger     = logging.getLogger(self.__class__.__name__)
        self.engagement = engagement          # Engagement instance or None
        self.config     = self.DEFAULT_CONFIG.copy()
        self._config_path = (
            MODULE_RESULTS_ROOT / 'config' / f'{self.MODULE_NAME.lower()}.json'
        )
        self.results_dir = MODULE_RESULTS_ROOT / self.MODULE_NAME.lower().replace(' ', '_')
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self._load_module_config()

    # ── Config persistence ─────────────────────────────────────────────────

    def _load_module_config(self) -> None:
        """Load per-module config from disk, merging with defaults."""
        try:
            if self._config_path.exists():
                with open(self._config_path) as f:
                    saved = json.load(f)
                self.config.update(saved)
        except Exception as e:
            self.logger.debug(f"Could not load module config: {e}")

    def _save_module_config(self) -> bool:
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            self.logger.error(f"Could not save module config: {e}")
            return False

    # ── Print helpers ──────────────────────────────────────────────────────

    def _print_success(self, msg: str) -> None:
        print(f'{Colors.OKGREEN}✓ {msg}{Colors.ENDC}')

    def _print_error(self, msg: str) -> None:
        print(f'{Colors.FAIL}✗ {msg}{Colors.ENDC}')
        self.logger.error(msg)

    def _print_warning(self, msg: str) -> None:
        print(f'{Colors.WARNING}⚠ {msg}{Colors.ENDC}')
        self.logger.warning(msg)

    def _print_info(self, msg: str) -> None:
        print(f'{Colors.OKCYAN}ℹ {msg}{Colors.ENDC}')

    def _print_header(self, title: str) -> None:
        bar = '─' * 60
        print(f'\n{Colors.BOLD}{Colors.HEADER}{bar}')
        print(f'  {title}')
        print(f'{bar}{Colors.ENDC}\n')

    def _print_table(self, headers: List[str], rows: List[List[str]]) -> None:
        """Print a simple formatted ASCII table."""
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(str(cell)))
        fmt = '  '.join(f'{{:<{w}}}' for w in widths)
        sep = '  '.join('─' * w for w in widths)
        print(f'{Colors.BOLD}  {fmt.format(*headers)}{Colors.ENDC}')
        print(f'  {sep}')
        for row in rows:
            cells = [str(c) for c in row]
            cells += [''] * (len(headers) - len(cells))
            print(f'  {fmt.format(*cells)}')

    # ── Scope validation ───────────────────────────────────────────────────

    def _validate_scope(self, target: str) -> bool:
        """
        Check if target is within the active engagement's scope.
        Returns True if no engagement is loaded (no scope restriction).
        Warns and returns False if out of scope.
        """
        if self.engagement is None:
            return True
        return self.engagement.is_in_scope(target)

    def _require_scope(self, target: str) -> bool:
        """Print error and return False if target is out of scope."""
        if not self._validate_scope(target):
            self._print_error(
                f"Target '{target}' is OUT OF SCOPE for engagement "
                f"'{self.engagement.name}'. Aborting."
            )
            self.logger.warning(
                f"[SCOPE VIOLATION] Target {target} blocked for engagement "
                f"{self.engagement.name}"
            )
            return False
        return True

    # ── Finding logging ────────────────────────────────────────────────────

    def _log_finding(
        self,
        title: str,
        severity: str,
        description: str,
        affected: str = '',
        recommendation: str = '',
        evidence: Optional[List[str]] = None,
        cve: Optional[str] = None,
    ) -> None:
        """
        Emit a finding to the active engagement.
        No-op if no engagement is loaded (just logs to file).
        """
        if self.engagement is not None:
            self.engagement.add_finding(
                title=title,
                severity=severity,
                description=description,
                affected=affected,
                recommendation=recommendation,
                evidence=evidence or [],
                cve=cve,
                source=self.MODULE_NAME,
            )
            self._print_success(
                f"Finding logged → [{severity.upper()}] {title}"
            )
        else:
            self._print_info(
                f"Finding (no active engagement): [{severity.upper()}] {title}"
            )

    # ── Audit trail ────────────────────────────────────────────────────────

    def _audit(self, command: str, detail: str = '') -> None:
        """Write a line to the engagement audit log."""
        if self.engagement is not None:
            self.engagement.audit(self.MODULE_NAME, command, detail)

    def precmd(self, line: str) -> str:
        """Hook: audit every command before execution."""
        if line.strip():
            self._audit('CMD', line.strip())
        return line

    # ── Shared commands ────────────────────────────────────────────────────

    def do_config(self, arg: str) -> None:
        """
        View or set module configuration.

        Usage:
            config show             - display all settings
            config <key> <value>    - set a value
            config reset            - reset to defaults
        """
        parts = arg.strip().split(maxsplit=1)

        if not parts or parts[0] == 'show':
            self._print_header(f'{self.MODULE_NAME} Configuration')
            rows = [[k, str(v)] for k, v in sorted(self.config.items())]
            self._print_table(['Key', 'Value'], rows)
            print()
            return

        if parts[0] == 'reset':
            self.config = self.DEFAULT_CONFIG.copy()
            if self._save_module_config():
                self._print_success("Configuration reset to defaults.")
            return

        if len(parts) < 2:
            self._print_error("Usage: config <key> <value> | config show | config reset")
            return

        key, value = parts[0], parts[1]
        if key not in self.DEFAULT_CONFIG:
            self._print_warning(f"Unknown key '{key}'. Available: {', '.join(self.DEFAULT_CONFIG)}")
            return

        # Type coercion based on default type
        default_val = self.DEFAULT_CONFIG[key]
        try:
            if isinstance(default_val, bool):
                value = value.lower() in ('true', '1', 'yes', 'on')
            elif isinstance(default_val, int):
                value = int(value)
            elif isinstance(default_val, float):
                value = float(value)
        except ValueError:
            self._print_error(
                f"'{key}' expects type {type(default_val).__name__}, got: {value}"
            )
            return

        self.config[key] = value
        if self._save_module_config():
            self._print_success(f"Set {key} = {value}")

    def do_back(self, _arg: str) -> bool:
        """Return to the main toolkit menu."""
        return True

    def do_exit(self, arg: str) -> bool:
        """Return to the main toolkit menu."""
        return self.do_back(arg)

    def do_quit(self, arg: str) -> bool:
        """Alias for back."""
        return self.do_back(arg)

    def emptyline(self) -> None:
        """Do nothing on empty input."""
        pass

    def default(self, line: str) -> None:
        """Handle unknown commands."""
        self._print_error(f"Unknown command: '{line}'")
        self._print_info("Type 'help' for available commands.")

    # ── Utility helpers ────────────────────────────────────────────────────

    def _timestamp(self) -> str:
        return datetime.now().strftime('%Y%m%d_%H%M%S')

    def _save_output(self, content: str, prefix: str = 'output', ext: str = 'txt') -> Path:
        """Write content to a timestamped file in results_dir and return the path."""
        path = self.results_dir / f'{prefix}_{self._timestamp()}.{ext}'
        path.write_text(content, encoding='utf-8')
        return path

    def _resolve_host(self, target: str) -> Optional[str]:
        """Resolve hostname to IP. Returns None on failure."""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None

    @staticmethod
    def _is_valid_ip(target: str) -> bool:
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_target(target: str) -> bool:
        """Accept IP, CIDR, or hostname."""
        if not target:
            return False
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
        hostname_re = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
            r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(hostname_re.match(target))
