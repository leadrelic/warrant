#!/usr/bin/env python3
"""
Penetration Testing Toolkit
A comprehensive command-line interface for authorized penetration testing.

Author: Dakota
Version: 3.0
"""

import cmd
import signal
import sys
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime
import json

from Modules.nmap import NmapModule
from Modules.trace import IPTraceModule
from Modules.vuln_scan import VulnerabilityScanningModule
from Modules.pass_crack import PasswordCrackingModule
from Modules.hashing import EncryptionDecryptionModule
from Modules.dictionary import PasswordDictionaryCreator
from Modules.osint import OSINTModule
from Modules.fuzzer import FuzzerModule
from Modules.engagement import EngagementModule, Engagement, list_engagements, load_engagement
from Modules.reporter import ReporterModule


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    DIM = '\033[2m'


class Config:
    """Configuration manager for the toolkit."""
    
    CONFIG_FILE = Path.home() / '.pentest_toolkit' / 'config.json'
    
    DEFAULT_CONFIG = {
        'scan_timeout': 300,
        'external_tools_path': '/usr/bin',
        'default_wordlist': '/usr/share/wordlists/rockyou.txt',
        'log_level': 'INFO',
        'color_output': True,
        'auto_save_results': True,
        'results_dir': str(Path.home() / '.pentest_toolkit' / 'results')
    }
    
    def __init__(self):
        self.config = self.load_config()
    
    def load_config(self) -> dict:
        """Load configuration from file or create default."""
        try:
            if self.CONFIG_FILE.exists():
                with open(self.CONFIG_FILE, 'r') as f:
                    return {**self.DEFAULT_CONFIG, **json.load(f)}
        except Exception as e:
            logging.warning(f"Could not load config: {e}")
        
        return self.DEFAULT_CONFIG.copy()
    
    def save_config(self) -> bool:
        """Save current configuration to file."""
        try:
            self.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(self.CONFIG_FILE, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            logging.error(f"Failed to save config: {e}")
            return False
    
    def get(self, key: str, default=None):
        """Get configuration value."""
        return self.config.get(key, default)
    
    def set(self, key: str, value) -> None:
        """Set configuration value."""
        self.config[key] = value


class Logger:
    """Enhanced logging system with session tracking."""
    
    def __init__(self, config: Config):
        self.config = config
        self.log_dir = Path.home() / '.pentest_toolkit' / 'logs'
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Session-specific log file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        session_log = self.log_dir / f'session_{timestamp}.log'
        
        # Configure logging
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=getattr(logging, config.get('log_level', 'INFO')),
            format=log_format,
            handlers=[
                logging.FileHandler(session_log),
                logging.FileHandler(self.log_dir / 'pentest_toolkit.log')
            ]
        )
        
        self.logger = logging.getLogger('PentestToolkit')
        self.logger.info(f"Session started: {timestamp}")


def signal_handler(sig, frame):
    """Handle interrupt signals gracefully."""
    print(f'\n{Colors.WARNING}Caught interrupt signal, exiting...{Colors.ENDC}')
    logging.info("Toolkit terminated by user interrupt")
    sys.exit(0)


class PentestTool(cmd.Cmd):
    """
    Advanced Penetration Testing Toolkit CLI.
    
    Provides an interactive shell for executing various penetration testing
    operations including network scanning, vulnerability assessment, password
    cracking, and more.
    """
    
    def __init__(self):
        super().__init__()
        self.config = Config()
        self.logger = Logger(self.config)
        self.use_colors = self.config.get('color_output', True)

        # Active engagement (shared across all modules)
        self._engagement: Optional[Engagement] = None
        self._update_prompt()

        # Module availability cache
        self._module_status = {}

    def _update_prompt(self) -> None:
        """Reflect active engagement in the prompt."""
        if self._engagement:
            self.prompt = (
                f'{Colors.OKGREEN}(pentest){Colors.ENDC}'
                f'{Colors.DIM}[{self._engagement.name}]{Colors.ENDC} '
            )
        else:
            self.prompt = f'{Colors.OKGREEN}(pentest){Colors.ENDC} '
        
    @property
    def intro(self) -> str:
        """Generate dynamic intro message."""
        eng_line = (
            f"{Colors.OKGREEN}  Active engagement: {self._engagement.name}  "
            f"[{self._engagement.client}]{Colors.ENDC}\n"
            if self._engagement else
            f"{Colors.DIM}  No engagement loaded. Use 'engagement' to start one.{Colors.ENDC}\n"
        )
        banner = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════════════╗
║          🔒  PENETRATION TESTING TOOLKIT  v3.0  🔒                   ║
║          Authorized Security Assessment Platform                       ║
╚══════════════════════════════════════════════════════════════════════╝{Colors.ENDC}

{eng_line}
{Colors.OKCYAN}  Type 'help' or '?' to list commands.{Colors.ENDC}

{Colors.BOLD}  Engagement & Reporting:{Colors.ENDC}
    engagement          - Manage engagements (scope, findings, audit)
    report              - Generate HTML/PDF/JSON/CSV reports

{Colors.BOLD}  Recon & OSINT:{Colors.ENDC}
    osint               - OSINT (theHarvester, Subfinder, Shodan, DNS, crt.sh)
    iptrace             - IP geolocation and network intelligence

{Colors.BOLD}  Scanning:{Colors.ENDC}
    nmap                - Network mapping and port scanning
    vulnscan            - Vulnerability assessment (Nikto, NSE)
    fuzzer              - Web directory/parameter fuzzing (gobuster, ffuf)

{Colors.BOLD}  Exploitation Support:{Colors.ENDC}
    password_cracking   - Hash cracking (dictionary, brute force, hybrid)
    encryption_decryption - Encrypt/decrypt files and hashes
    dictionary_creator  - Build custom wordlists

{Colors.BOLD}  Utilities:{Colors.ENDC}
    status              - Check module & tool availability
    config              - Configure global settings
    logging             - Adjust log verbosity
    clear / exit

{Colors.WARNING}  ⚠  For authorized testing only. Obtain written permission before use.{Colors.ENDC}
{Colors.HEADER}{'═'*72}{Colors.ENDC}
"""
        return banner if self.use_colors else self._strip_colors(banner)
    
    @staticmethod
    def _strip_colors(text: str) -> str:
        """Remove ANSI color codes from text."""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def _print_success(self, message: str) -> None:
        """Print success message."""
        print(f'{Colors.OKGREEN}✓ {message}{Colors.ENDC}')
    
    def _print_error(self, message: str) -> None:
        """Print error message."""
        print(f'{Colors.FAIL}✗ {message}{Colors.ENDC}')
    
    def _print_warning(self, message: str) -> None:
        """Print warning message."""
        print(f'{Colors.WARNING}⚠ {message}{Colors.ENDC}')
    
    def _print_info(self, message: str) -> None:
        """Print info message."""
        print(f'{Colors.OKCYAN}ℹ {message}{Colors.ENDC}')
    
    def _check_module_availability(self, module_class, module_name: str) -> bool:
        """Check if a module is available and cache the result."""
        if module_name in self._module_status:
            return self._module_status[module_name]
        
        try:
            module_class()
            self._module_status[module_name] = True
            return True
        except Exception as e:
            logging.debug(f"Module {module_name} unavailable: {e}")
            self._module_status[module_name] = False
            return False
    
    def _run_module(self, module_class, module_name: str, error_msg: str) -> None:
        """Generic module runner with error handling — passes active engagement."""
        try:
            self._print_info(f"Launching {module_name} module...")
            try:
                instance = module_class(engagement=self._engagement)
            except TypeError:
                instance = module_class()   # legacy modules don't accept engagement kwarg
            instance.cmdloop()
            self._print_success(f"{module_name} module exited. Check logs for details.")
            logging.info(f"{module_name} module session completed")
        except KeyboardInterrupt:
            self._print_warning("Returning to main menu...")
        except ImportError as e:
            self._print_error(f"Module import failed: {e}")
            self._print_info("Please ensure all dependencies are installed.")
            logging.error(f"{module_name} import error: {e}")
        except Exception as e:
            self._print_error(f"{error_msg}: {e}")
            logging.error(f"{module_name} error: {e}")
    
    # ===== Command Implementations =====

    # ── Engagement ────────────────────────────────────────────────────────

    def do_engagement(self, arg: str) -> None:
        """
        Launch the Engagement Management module.

        Usage: engagement

        Manage engagements: client info, scope, findings, audit trail.
        All other modules will respect the active engagement's scope.
        """
        try:
            self._print_info("Launching Engagement module...")
            module = EngagementModule(engagement=self._engagement)
            module.cmdloop()
            # Propagate engagement state back to main toolkit
            self._engagement = module.engagement
            self._update_prompt()
            if self._engagement:
                self._print_success(
                    f"Active engagement: {self._engagement.name}  [{self._engagement.client}]"
                )
        except KeyboardInterrupt:
            self._print_warning("Returning to main menu...")
        except Exception as e:
            self._print_error(f"Engagement module error: {e}")
            logging.error(f"Engagement module error: {e}")

    def do_report(self, arg: str) -> None:
        """
        Launch the Report Generator module.

        Usage: report

        Generate HTML, PDF, JSON, or CSV reports from engagement findings.
        Requires an active engagement (run 'engagement' first).
        """
        if self._engagement is None:
            self._print_warning(
                "No engagement loaded. Start one with 'engagement → new' or 'engagement → load'."
            )
            return
        self._run_module(ReporterModule, "Reporter", "Report generation failed")

    # ── New Recon/Scan modules ────────────────────────────────────────────

    def do_osint(self, arg: str) -> None:
        """
        Launch the OSINT reconnaissance module.

        Usage: osint

        Tools: theHarvester, Subfinder, Amass, DNSRecon, Shodan, crt.sh, whois.
        """
        self._run_module(OSINTModule, "OSINT", "OSINT module error")

    def do_fuzzer(self, arg: str) -> None:
        """
        Launch the Web Fuzzer module.

        Usage: fuzzer

        Tools: gobuster, ffuf, feroxbuster, built-in Python fuzzer.
        """
        self._run_module(FuzzerModule, "Fuzzer", "Fuzzer module error")

    # Alias
    def do_fuzz(self, arg: str) -> None:
        """Alias for fuzzer."""
        self.do_fuzzer(arg)

    # ── Quick engagement shortcuts ────────────────────────────────────────

    def do_scope(self, arg: str) -> None:
        """
        Quick scope check from the main menu.

        Usage: scope <target>

        Shows whether the target is in scope for the active engagement.
        """
        if self._engagement is None:
            self._print_warning("No engagement loaded.")
            return
        target = arg.strip()
        if not target:
            self._print_info(
                f"Scope: {', '.join(self._engagement.scope) if self._engagement.scope else 'Unrestricted'}"
            )
            return
        if self._engagement.is_in_scope(target):
            self._print_success(f"'{target}' is IN SCOPE ✓")
        else:
            self._print_error(f"'{target}' is OUT OF SCOPE ✗")

    def do_findings(self, arg: str) -> None:
        """
        Quick findings summary from the main menu.

        Usage: findings
        """
        if self._engagement is None:
            self._print_warning("No engagement loaded.")
            return
        counts = self._engagement.finding_counts
        print(
            f"\n  Findings for {Colors.BOLD}{self._engagement.name}{Colors.ENDC}:\n"
            f"  {Colors.FAIL}{counts.get('critical',0)} Critical{Colors.ENDC}  "
            f"{Colors.WARNING}{counts.get('high',0)} High{Colors.ENDC}  "
            f"{Colors.OKBLUE}{counts.get('medium',0)} Medium{Colors.ENDC}  "
            f"{counts.get('low',0)} Low  "
            f"{Colors.DIM}{counts.get('info',0)} Info{Colors.ENDC}\n"
        )

    # ── Original modules ──────────────────────────────────────────────────

    def do_nmap(self, arg: str) -> None:
        """
        Launch the Nmap network scanning module.
        
        Usage: nmap
        
        The Nmap module provides network mapping, port scanning, service
        detection, and OS fingerprinting capabilities.
        """
        self._run_module(
            NmapModule,
            "Nmap",
            "Please ensure Nmap is correctly installed and configured"
        )
    
    def do_iptrace(self, arg: str) -> None:
        """
        Launch the IP trace module.
        
        Usage: iptrace
        
        Trace the network path to a specified IP address or hostname.
        """
        self._run_module(
            IPTraceModule,
            "IP Trace",
            "Please ensure the IP Trace module is configured correctly"
        )
    
    def do_vulnscan(self, arg: str) -> None:
        """
        Launch the vulnerability scanning module.
        
        Usage: vulnscan
        
        Perform comprehensive vulnerability assessments on target systems.
        """
        self._run_module(
            VulnerabilityScanningModule,
            "Vulnerability Scanning",
            "Ensure the target is reachable and try again"
        )
    
    def do_password_cracking(self, arg: str) -> None:
        """
        Launch the password cracking module.
        
        Usage: password_cracking
        
        Attempt to crack passwords using dictionary attacks, brute force,
        and other methods.
        """
        self._run_module(
            PasswordCrackingModule,
            "Password Cracking",
            "Verify wordlist and other configurations"
        )
    
    def do_encryption_decryption(self, arg: str) -> None:
        """
        Launch the encryption/decryption module.
        
        Usage: encryption_decryption
        
        Encrypt or decrypt files using various algorithms.
        """
        self._run_module(
            EncryptionDecryptionModule,
            "Encryption/Decryption",
            "Check the provided keys and files"
        )
    
    def do_dictionary_creator(self, arg: str) -> None:
        """
        Launch the password dictionary creator module.
        
        Usage: dictionary_creator
        
        Create custom password dictionaries for brute-force attacks.
        """
        self._run_module(
            PasswordDictionaryCreator,
            "Dictionary Creator",
            "Verify dictionary settings and try again"
        )
    
    def do_status(self, arg: str) -> None:
        """
        Display the status of all modules.
        
        Usage: status
        
        Shows which modules are available and which have dependency issues.
        """
        print(f"\n{Colors.BOLD}Module Status:{Colors.ENDC}\n")
        
        modules = [
            (NmapModule,                 "Nmap"),
            (IPTraceModule,              "IP Trace"),
            (VulnerabilityScanningModule,"Vulnerability Scanning"),
            (PasswordCrackingModule,     "Password Cracking"),
            (EncryptionDecryptionModule, "Encryption/Decryption"),
            (PasswordDictionaryCreator,  "Dictionary Creator"),
            (OSINTModule,                "OSINT"),
            (FuzzerModule,               "Fuzzer"),
            (EngagementModule,           "Engagement"),
            (ReporterModule,             "Reporter"),
        ]

        # Show active engagement
        if self._engagement:
            print(f"  {Colors.OKGREEN}Active engagement:{Colors.ENDC} {self._engagement.name}  [{self._engagement.client}]")
        else:
            print(f"  {Colors.DIM}No engagement loaded.{Colors.ENDC}")
        print()
        
        for module_class, name in modules:
            status = "✓ Available" if self._check_module_availability(module_class, name) else "✗ Not Available"
            color = Colors.OKGREEN if "Available" in status else Colors.FAIL
            print(f"  {color}{name:.<30} {status}{Colors.ENDC}")
        
        print()
    
    def do_config(self, arg: str) -> None:
        """
        Configure toolkit settings.
        
        Usage: config [key] [value]
               config show
               config reset
        
        Examples:
            config show                              - Display all settings
            config scan_timeout 600                  - Set scan timeout to 600s
            config default_wordlist /path/to/list    - Set default wordlist
            config reset                             - Reset to defaults
        """
        args = arg.split(maxsplit=1)
        
        if not args or args[0] == 'show':
            print(f"\n{Colors.BOLD}Current Configuration:{Colors.ENDC}\n")
            for key, value in sorted(self.config.config.items()):
                print(f"  {Colors.OKCYAN}{key:.<30} {value}{Colors.ENDC}")
            print()
            return
        
        if args[0] == 'reset':
            self.config.config = self.config.DEFAULT_CONFIG.copy()
            if self.config.save_config():
                self._print_success("Configuration reset to defaults")
            return
        
        if len(args) < 2:
            self._print_error("Usage: config [key] [value] | config show | config reset")
            return
        
        key, value = args[0], args[1]
        
        # Type conversion for known keys
        if key in ['scan_timeout']:
            try:
                value = int(value)
            except ValueError:
                self._print_error(f"'{key}' must be an integer")
                return
        elif key in ['color_output', 'auto_save_results']:
            value = value.lower() in ['true', '1', 'yes', 'on']
        
        self.config.set(key, value)
        if self.config.save_config():
            self._print_success(f"Set {key} = {value}")
            logging.info(f"Configuration updated: {key} = {value}")
    
    def do_logging(self, arg: str) -> None:
        """
        Toggle logging level.
        
        Usage: logging [on|off|level]
        
        Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
        
        Examples:
            logging on       - Enable INFO level logging
            logging off      - Set to CRITICAL (minimal logging)
            logging DEBUG    - Enable debug logging
        """
        if not arg:
            current_level = logging.getLogger().getEffectiveLevel()
            level_name = logging.getLevelName(current_level)
            self._print_info(f"Current logging level: {level_name}")
            return
        
        arg = arg.upper()
        
        if arg == 'ON':
            level = logging.INFO
            self._print_success("Logging enabled (INFO level)")
        elif arg == 'OFF':
            level = logging.CRITICAL
            self._print_success("Logging disabled")
        elif arg in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            level = getattr(logging, arg)
            self._print_success(f"Logging level set to {arg}")
        else:
            self._print_error("Usage: logging [on|off|DEBUG|INFO|WARNING|ERROR|CRITICAL]")
            return
        
        logging.getLogger().setLevel(level)
        self.config.set('log_level', logging.getLevelName(level))
        self.config.save_config()
    
    def do_clear(self, arg: str) -> None:
        """
        Clear the terminal screen.
        
        Usage: clear
        """
        import os
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def do_exit(self, arg: str) -> bool:
        """
        Exit the pentesting toolkit.
        
        Usage: exit | quit
        """
        print(f'\n{Colors.OKGREEN}Exiting the pentesting toolkit. Stay safe! 🔒{Colors.ENDC}\n')
        logging.info("Toolkit session ended normally")
        return True
    
    def do_quit(self, arg: str) -> bool:
        """Alias for exit."""
        return self.do_exit(arg)
    
    # ===== Command Aliases =====
    
    def do_scan(self, arg: str) -> None:
        """Alias for nmap."""
        self.do_nmap(arg)
    
    def do_trace(self, arg: str) -> None:
        """Alias for iptrace."""
        self.do_iptrace(arg)
    
    def do_vuln(self, arg: str) -> None:
        """Alias for vulnscan."""
        self.do_vulnscan(arg)
    
    def do_crack(self, arg: str) -> None:
        """Alias for password_cracking."""
        self.do_password_cracking(arg)
    
    def do_crypto(self, arg: str) -> None:
        """Alias for encryption_decryption."""
        self.do_encryption_decryption(arg)
    
    def do_dict(self, arg: str) -> None:
        """Alias for dictionary_creator."""
        self.do_dictionary_creator(arg)
    
    # ===== Tab Completion =====
    
    def complete_config(self, text: str, line: str, begidx: int, endidx: int) -> list:
        """Autocomplete for config command."""
        options = ['show', 'reset'] + list(self.config.DEFAULT_CONFIG.keys())
        return [opt for opt in options if opt.startswith(text)]
    
    def complete_logging(self, text: str, line: str, begidx: int, endidx: int) -> list:
        """Autocomplete for logging command."""
        levels = ['on', 'off', 'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        return [level for level in levels if level.startswith(text.upper())]
    
    def emptyline(self) -> None:
        """Do nothing on empty line (override default repeat behavior)."""
        pass
    
    def default(self, line: str) -> None:
        """Handle unknown commands."""
        self._print_error(f"Unknown command: {line}")
        self._print_info("Type 'help' for available commands")


def main():
    """Main entry point for the toolkit."""
    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        toolkit = PentestTool()
        toolkit.cmdloop()
    except KeyboardInterrupt:
        print(f'\n{Colors.WARNING}Exiting the pentesting toolkit. Goodbye!{Colors.ENDC}')
        sys.exit(0)
    except Exception as e:
        logging.critical(f"Fatal error: {e}", exc_info=True)
        print(f'{Colors.FAIL}Fatal error occurred. Check logs for details.{Colors.ENDC}')
        sys.exit(1)


if __name__ == '__main__':
    main()
