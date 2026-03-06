"""
OSINT Module
Open-source intelligence gathering for penetration testing engagements.

Wraps industry-standard tools and APIs:
  - theHarvester  (email, subdomain, host enumeration)
  - Subfinder     (passive subdomain discovery)
  - Amass         (in-depth subdomain enumeration)
  - DNSRecon      (DNS reconnaissance)
  - Shodan API    (exposed services / IoT / asset discovery)
  - whois         (domain registration info)
  - crt.sh        (certificate transparency — no API key needed)
  - Built-in DNS  (A, MX, TXT, NS records via socket/subprocess)
"""

import json
import socket
import subprocess
import shutil
import logging
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional, List

from Modules.base_module import BaseModule, Colors

logger = logging.getLogger(__name__)


class OSINTModule(BaseModule):
    """
    OSINT reconnaissance module for authorized engagements.

    Commands:
        theharvester <domain>       - Run theHarvester recon
        subfinder    <domain>       - Passive subdomain enumeration
        amass        <domain>       - In-depth subdomain enumeration
        dnsrecon     <domain>       - DNS reconnaissance
        dns          <domain>       - Quick DNS record lookup (built-in)
        crtsh        <domain>       - Certificate transparency lookup
        shodan       <query>        - Shodan search (requires API key)
        whois        <target>       - WHOIS lookup
        emails       <domain>       - Harvest emails from multiple sources
        batch        <file>         - Run full recon on each target in file
        tools                       - Check which tools are installed
        results                     - View saved OSINT results
    """

    MODULE_NAME   = "OSINT"
    MODULE_DESC   = "OSINT and passive reconnaissance"
    DEFAULT_CONFIG = {
        'shodan_api_key':    '',
        'timeout':           60,
        'dns_servers':       '8.8.8.8,1.1.1.1',
        'harvester_sources': 'google,bing,yahoo,linkedin,twitter',
        'save_results':      True,
        'subfinder_threads': 10,
        'amass_timeout':     120,
    }

    prompt = '(osint) '
    intro  = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
║                 OSINT Reconnaissance Module                    ║
║  theHarvester • Subfinder • Amass • DNSRecon • Shodan          ║
╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}

Commands:
  theharvester <domain>  - Email/subdomain/host recon
  subfinder <domain>     - Passive subdomain discovery
  amass <domain>         - Deep subdomain enumeration
  dnsrecon <domain>      - Full DNS reconnaissance
  dns <domain>           - Quick DNS records (A/MX/TXT/NS)
  crtsh <domain>         - Certificate transparency lookup
  shodan <query>         - Shodan search (set API key first)
  whois <target>         - WHOIS information
  emails <domain>        - Harvest emails from public sources
  batch <targets.txt>    - Full recon on each line in file
  tools                  - Check tool availability
  results                - Browse saved results

Type 'back' to return to main menu.
"""

    # ── tools check ───────────────────────────────────────────────────────

    def do_tools(self, _arg: str) -> None:
        """Show which OSINT tools are installed."""
        tools = {
            'theHarvester':  'theHarvester',
            'subfinder':     'subfinder',
            'amass':         'amass',
            'dnsrecon':      'dnsrecon',
            'whois':         'whois',
            'dig':           'dig',
            'nmap':          'nmap',
        }
        self._print_header("Tool Availability")
        for name, cmd in tools.items():
            found = shutil.which(cmd) is not None
            color  = Colors.OKGREEN if found else Colors.FAIL
            status = "✓ installed" if found else "✗ not found"
            print(f"  {color}{name:<20} {status}{Colors.ENDC}")

        # Shodan API
        api_set = bool(self.config.get('shodan_api_key'))
        color   = Colors.OKGREEN if api_set else Colors.WARNING
        print(f"  {color}{'Shodan API key':<20} {'✓ configured' if api_set else '⚠ not set (config shodan_api_key <key>)'}{Colors.ENDC}")
        print()

    # ── theHarvester ──────────────────────────────────────────────────────

    def do_theharvester(self, arg: str) -> None:
        """
        Run theHarvester email/subdomain/host enumeration.

        Usage: theharvester <domain> [sources]

        Examples:
            theharvester example.com
            theharvester example.com google,bing,linkedin
        """
        parts   = arg.strip().split()
        if not parts:
            self._print_error("Usage: theharvester <domain> [sources]")
            return

        domain  = parts[0]
        sources = parts[1] if len(parts) > 1 else self.config['harvester_sources']

        if not self._require_scope(domain):
            return

        if not shutil.which('theHarvester'):
            self._print_error(
                "theHarvester not found. Install with:\n"
                "  pip install theHarvester  or  apt-get install theharvester"
            )
            return

        out_file = self.results_dir / f'harvester_{domain}_{self._timestamp()}.json'
        cmd = [
            'theHarvester',
            '-d', domain,
            '-b', sources,
            '-f', str(out_file.with_suffix('')),   # theHarvester adds extension
        ]

        self._print_info(f"Running theHarvester on {domain}  (sources: {sources})")
        self._audit('theharvester', f"{domain} sources={sources}")
        self._run_tool(cmd, out_file, "theHarvester")

    # ── Subfinder ─────────────────────────────────────────────────────────

    def do_subfinder(self, arg: str) -> None:
        """
        Passive subdomain discovery with Subfinder.

        Usage: subfinder <domain>
        """
        domain = arg.strip()
        if not domain:
            self._print_error("Usage: subfinder <domain>")
            return

        if not self._require_scope(domain):
            return

        if not shutil.which('subfinder'):
            self._print_error(
                "Subfinder not found. Install from:\n"
                "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
                "  or: apt-get install subfinder"
            )
            return

        out_file = self.results_dir / f'subfinder_{domain}_{self._timestamp()}.txt'
        cmd = [
            'subfinder', '-d', domain,
            '-t', str(self.config['subfinder_threads']),
            '-o', str(out_file), '-silent',
        ]

        self._print_info(f"Running Subfinder on {domain}...")
        self._audit('subfinder', domain)
        self._run_tool(cmd, out_file, "Subfinder")

    # ── Amass ─────────────────────────────────────────────────────────────

    def do_amass(self, arg: str) -> None:
        """
        In-depth subdomain enumeration with Amass.

        Usage: amass <domain> [passive|active]   (default: passive)

        Note: active mode may generate detectable traffic.
        """
        parts  = arg.strip().split()
        if not parts:
            self._print_error("Usage: amass <domain> [passive|active]")
            return

        domain = parts[0]
        mode   = parts[1] if len(parts) > 1 else 'passive'

        if not self._require_scope(domain):
            return

        if not shutil.which('amass'):
            self._print_error(
                "Amass not found. Install from:\n"
                "  apt-get install amass  or  go install github.com/owasp-amass/amass/v4/...@latest"
            )
            return

        out_file = self.results_dir / f'amass_{domain}_{self._timestamp()}.txt'
        timeout  = self.config['amass_timeout']

        cmd = ['amass', 'enum', '-d', domain, '-o', str(out_file), '-timeout', str(timeout)]
        if mode == 'passive':
            cmd.append('-passive')

        self._print_info(f"Running Amass ({mode}) on {domain}  (timeout: {timeout}s)...")
        self._audit('amass', f"{domain} mode={mode}")
        self._run_tool(cmd, out_file, "Amass")

    # ── DNSRecon ──────────────────────────────────────────────────────────

    def do_dnsrecon(self, arg: str) -> None:
        """
        DNS reconnaissance with dnsrecon.

        Usage: dnsrecon <domain> [type]

        Types: std (default), brt, axfr, goo, bing, yand, crt, snoop
        """
        parts  = arg.strip().split()
        if not parts:
            self._print_error("Usage: dnsrecon <domain> [type]")
            return

        domain   = parts[0]
        dns_type = parts[1] if len(parts) > 1 else 'std'

        if not self._require_scope(domain):
            return

        if not shutil.which('dnsrecon'):
            self._print_error(
                "dnsrecon not found. Install with:\n"
                "  pip install dnsrecon  or  apt-get install dnsrecon"
            )
            return

        out_file = self.results_dir / f'dnsrecon_{domain}_{self._timestamp()}.json'
        cmd = [
            'dnsrecon', '-d', domain, '-t', dns_type,
            '-j', str(out_file),
        ]

        self._print_info(f"Running DNSRecon ({dns_type}) on {domain}...")
        self._audit('dnsrecon', f"{domain} type={dns_type}")
        self._run_tool(cmd, out_file, "DNSRecon")

    # ── Built-in DNS ──────────────────────────────────────────────────────

    def do_dns(self, arg: str) -> None:
        """
        Quick DNS record lookup (no external tools required).

        Usage: dns <domain>

        Retrieves: A, AAAA, MX, NS, TXT, CNAME records via system dig.
        """
        domain = arg.strip()
        if not domain:
            self._print_error("Usage: dns <domain>")
            return

        self._audit('dns', domain)
        self._print_header(f"DNS Records: {domain}")

        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        results: List[str] = []

        for rtype in record_types:
            try:
                result = subprocess.run(
                    ['dig', '+short', domain, rtype],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout.strip():
                    print(f"  {Colors.BOLD}{rtype:<8}{Colors.ENDC}  {result.stdout.strip()}")
                    results.append(f"{rtype}: {result.stdout.strip()}")
            except FileNotFoundError:
                # dig not available — fall back to socket for A records
                if rtype == 'A':
                    try:
                        ip = socket.gethostbyname(domain)
                        print(f"  {Colors.BOLD}A       {Colors.ENDC}  {ip}")
                        results.append(f"A: {ip}")
                    except socket.gaierror:
                        self._print_error(f"Could not resolve {domain}")
                break
            except subprocess.TimeoutExpired:
                self._print_warning(f"Timeout on {rtype} lookup.")

        if results and self.config['save_results']:
            out = self._save_output(
                '\n'.join(results),
                prefix=f'dns_{domain}',
                ext='txt'
            )
            self._print_info(f"Saved: {out}")
        print()

    # ── crt.sh ────────────────────────────────────────────────────────────

    def do_crtsh(self, arg: str) -> None:
        """
        Certificate transparency lookup via crt.sh (no API key needed).

        Usage: crtsh <domain>

        Finds subdomains/certificates registered for the domain.
        """
        domain = arg.strip()
        if not domain:
            self._print_error("Usage: crtsh <domain>")
            return

        self._audit('crtsh', domain)
        self._print_info(f"Querying crt.sh for {domain}...")

        try:
            resp = requests.get(
                f'https://crt.sh/?q=%.{domain}&output=json',
                timeout=self.config['timeout'],
                headers={'Accept': 'application/json'}
            )
            if resp.status_code != 200:
                self._print_error(f"crt.sh returned HTTP {resp.status_code}")
                return

            data = resp.json()
        except requests.exceptions.RequestException as e:
            self._print_error(f"crt.sh request failed: {e}")
            return
        except json.JSONDecodeError:
            self._print_error("Failed to parse crt.sh response.")
            return

        # Deduplicate subdomains
        subdomains = set()
        for entry in data:
            names = entry.get('name_value', '').split('\n')
            for name in names:
                name = name.strip().lstrip('*.')
                if name and domain in name:
                    subdomains.add(name)

        if not subdomains:
            self._print_info("No certificates found.")
            return

        self._print_header(f"crt.sh Results: {domain}  ({len(subdomains)} unique)")
        for sub in sorted(subdomains):
            print(f"  {Colors.OKCYAN}{sub}{Colors.ENDC}")
        print()

        if self.config['save_results']:
            out = self._save_output(
                '\n'.join(sorted(subdomains)),
                prefix=f'crtsh_{domain}',
                ext='txt'
            )
            self._print_info(f"Saved: {out}")

    # ── Shodan ────────────────────────────────────────────────────────────

    def do_shodan(self, arg: str) -> None:
        """
        Search Shodan for exposed services.

        Usage: shodan <query>

        Examples:
            shodan hostname:example.com
            shodan net:203.0.113.0/24
            shodan org:"Example Corp"

        Requires: config shodan_api_key <your-key>
        """
        query = arg.strip()
        if not query:
            self._print_error("Usage: shodan <query>")
            return

        api_key = self.config.get('shodan_api_key', '')
        if not api_key:
            self._print_error(
                "Shodan API key not set.\n"
                "  Register at https://shodan.io and run:\n"
                "  config shodan_api_key <your-key>"
            )
            return

        self._audit('shodan', query)
        self._print_info(f"Querying Shodan: {query}")

        try:
            resp = requests.get(
                'https://api.shodan.io/shodan/host/search',
                params={'key': api_key, 'query': query, 'minify': 'false'},
                timeout=self.config['timeout'],
            )
            if resp.status_code == 401:
                self._print_error("Invalid Shodan API key.")
                return
            if resp.status_code == 402:
                self._print_error("Shodan API requires a paid plan for this query.")
                return
            if resp.status_code != 200:
                self._print_error(f"Shodan returned HTTP {resp.status_code}")
                return

            data = resp.json()
        except requests.exceptions.RequestException as e:
            self._print_error(f"Shodan request failed: {e}")
            return

        total   = data.get('total', 0)
        matches = data.get('matches', [])
        self._print_header(f"Shodan Results ({total} total, showing {len(matches)})")

        for match in matches:
            ip      = match.get('ip_str', '?')
            port    = match.get('port', '?')
            product = match.get('product', '')
            version = match.get('version', '')
            org     = match.get('org', '')
            country = match.get('location', {}).get('country_name', '')
            vulns   = list(match.get('vulns', {}).keys())

            svc_str = f"{product} {version}".strip()
            print(
                f"  {Colors.OKBLUE}{ip:<18}{Colors.ENDC}:{Colors.BOLD}{port:<6}{Colors.ENDC}  "
                f"{svc_str:<30}  {org}  {country}"
            )
            if vulns:
                vuln_str = ', '.join(vulns[:5])
                print(f"    {Colors.FAIL}CVEs: {vuln_str}{Colors.ENDC}")

        if matches and self.config['save_results']:
            out = self._save_output(
                json.dumps(data, indent=2),
                prefix=f'shodan_{query[:30].replace(" ","_")}',
                ext='json'
            )
            self._print_info(f"Saved: {out}")
        print()

    # ── whois ─────────────────────────────────────────────────────────────

    def do_whois(self, arg: str) -> None:
        """
        WHOIS lookup.

        Usage: whois <domain-or-ip>
        """
        target = arg.strip()
        if not target:
            self._print_error("Usage: whois <domain-or-ip>")
            return

        self._audit('whois', target)

        if not shutil.which('whois'):
            self._print_error("'whois' binary not found. Install with: apt-get install whois")
            return

        self._print_info(f"WHOIS lookup: {target}")
        try:
            result = subprocess.run(
                ['whois', target],
                capture_output=True, text=True,
                timeout=self.config['timeout']
            )
            output = result.stdout or result.stderr
            print(output)
            if self.config['save_results']:
                out = self._save_output(output, prefix=f'whois_{target}', ext='txt')
                self._print_info(f"Saved: {out}")
        except subprocess.TimeoutExpired:
            self._print_error("WHOIS timed out.")
        except Exception as e:
            self._print_error(f"WHOIS error: {e}")

    # ── emails ────────────────────────────────────────────────────────────

    def do_emails(self, arg: str) -> None:
        """
        Harvest email addresses for a domain from public sources.

        Usage: emails <domain>

        Uses crt.sh + theHarvester (if installed) to collect emails.
        """
        domain = arg.strip()
        if not domain:
            self._print_error("Usage: emails <domain>")
            return

        if not self._require_scope(domain):
            return

        self._audit('emails', domain)
        self._print_header(f"Email Harvesting: {domain}")
        emails = set()

        # Try theHarvester
        if shutil.which('theHarvester'):
            self._print_info("Running theHarvester...")
            try:
                result = subprocess.run(
                    ['theHarvester', '-d', domain, '-b', 'google,bing,linkedin', '-l', '100'],
                    capture_output=True, text=True, timeout=120
                )
                for line in result.stdout.splitlines():
                    if '@' in line and domain.split('.')[0] in line.lower():
                        email = line.strip()
                        if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', email):
                            emails.add(email)
            except Exception:
                pass

        # Parse for emails in raw text from any gathering
        import re as _re
        email_re = _re.compile(rf'[a-zA-Z0-9._%+\-]+@{_re.escape(domain)}')

        if emails:
            for e in sorted(emails):
                print(f"  {Colors.OKGREEN}{e}{Colors.ENDC}")
            if self.config['save_results']:
                out = self._save_output(
                    '\n'.join(sorted(emails)),
                    prefix=f'emails_{domain}', ext='txt'
                )
                self._print_info(f"Saved: {out}  ({len(emails)} emails)")
        else:
            self._print_info("No emails found via automated sources.")
            self._print_info(
                "Tip: Try theHarvester manually for deeper search:\n"
                f"  theHarvester -d {domain} -b all -l 500"
            )
        print()

    # ── batch ─────────────────────────────────────────────────────────────

    def do_batch(self, arg: str) -> None:
        """
        Run full OSINT recon on each target in a file.

        Usage: batch <targets.txt>

        File format: one domain/IP per line.
        Runs: dns, crtsh, whois for each target.
        """
        path = Path(arg.strip())
        if not path.exists():
            self._print_error(f"File not found: {path}")
            return

        targets = [l.strip() for l in path.read_text().splitlines() if l.strip() and not l.startswith('#')]
        if not targets:
            self._print_warning("No targets found in file.")
            return

        self._print_header(f"Batch OSINT: {len(targets)} targets")
        for i, t in enumerate(targets, 1):
            print(f"\n{Colors.BOLD}[{i}/{len(targets)}] Target: {t}{Colors.ENDC}")
            if not self._require_scope(t):
                continue
            self.do_dns(t)
            if '.' in t and not self._is_valid_ip(t):  # it's a domain
                self.do_crtsh(t)
                self.do_whois(t)

        self._print_success("Batch recon complete.")

    # ── results ───────────────────────────────────────────────────────────

    def do_results(self, arg: str) -> None:
        """
        List saved OSINT results.

        Usage: results [filter]   (optional substring filter)
        """
        files = sorted(self.results_dir.iterdir()) if self.results_dir.exists() else []
        if arg.strip():
            files = [f for f in files if arg.strip().lower() in f.name.lower()]

        if not files:
            self._print_info("No results saved yet.")
            return

        self._print_header(f"Saved OSINT Results ({len(files)} files)")
        for f in files:
            size = f.stat().st_size
            ts   = datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
            print(f"  {Colors.OKCYAN}{f.name:<55}{Colors.ENDC}  {size:>8,} B  {ts}")
        print()

    # ── helpers ───────────────────────────────────────────────────────────

    def _run_tool(self, cmd: list, out_file: Path, tool_name: str) -> None:
        """Run a subprocess tool, stream output, and report on completion."""
        try:
            self._print_info(f"Command: {' '.join(cmd)}")
            proc = subprocess.run(
                cmd,
                timeout=max(self.config['timeout'], self.config.get('amass_timeout', 120)),
                text=True,
                capture_output=True,
            )
            output = proc.stdout + proc.stderr
            print(output)

            if self.config['save_results']:
                saved = self._save_output(output, prefix=tool_name.lower(), ext='txt')
                self._print_success(f"{tool_name} complete. Saved: {saved}")
            else:
                self._print_success(f"{tool_name} complete.")

        except subprocess.TimeoutExpired:
            self._print_error(f"{tool_name} timed out.")
        except FileNotFoundError:
            self._print_error(f"{tool_name} binary not found.")
        except Exception as e:
            self._print_error(f"{tool_name} error: {e}")
