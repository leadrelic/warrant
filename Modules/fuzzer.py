"""
Fuzzer Module
Web directory and parameter fuzzing for authorized penetration tests.

Wraps:
  - gobuster  (fast Go-based directory/DNS/vhost fuzzing)
  - ffuf      (fast web fuzzer — more flexible, supports parameter fuzzing)
  - feroxbuster (recursive content discovery)

Falls back to a built-in Python-based fuzzer if no tools are installed.
"""

import json
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from Modules.base_module import BaseModule, Colors


# Default wordlists (common locations on Kali / Parrot / Ubuntu with SecLists)
DEFAULT_WORDLISTS = [
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt',
    '/usr/share/wordlists/rockyou.txt',       # fallback for password fuzzing
]


def _find_wordlist() -> Optional[str]:
    """Return the first available default wordlist."""
    for wl in DEFAULT_WORDLISTS:
        if Path(wl).exists():
            return wl
    return None


class FuzzerModule(BaseModule):
    """
    Web fuzzing module — directory, DNS, vhost, and parameter discovery.

    Commands:
        gobuster  dir|dns|vhost <target>    - Run gobuster
        ffuf      <url>                     - Run ffuf (FUZZ keyword)
        ferox     <url>                     - Run feroxbuster recursive scan
        fuzz      <url>                     - Built-in Python fuzzer (no deps)
        vhost     <domain> <ip>             - Virtual host enumeration
        params    <url>                     - Parameter discovery
        wordlists                           - Show available wordlists
        tools                               - Check installed tools
        results                             - View saved scan results
    """

    MODULE_NAME    = "Fuzzer"
    MODULE_DESC    = "Web directory, DNS, and parameter fuzzing"
    DEFAULT_CONFIG = {
        'wordlist':        _find_wordlist() or '/usr/share/wordlists/dirb/common.txt',
        'threads':         50,
        'timeout':         300,
        'status_codes':    '200,204,301,302,307,401,403',
        'follow_redirects': True,
        'extensions':      'php,html,js,txt,bak,old,zip',
        'user_agent':      'Mozilla/5.0 (compatible; PentestToolkit/3.0)',
        'delay_ms':        0,
        'recursive':       False,
        'output_format':   'json',
    }

    prompt = '(fuzzer) '
    intro  = f"""
{Colors.HEADER}╔══════════════════════════════════════════════════════════════╗
║                   Web Fuzzer Module                            ║
║  gobuster • ffuf • feroxbuster • built-in fallback             ║
╚══════════════════════════════════════════════════════════════════╝{Colors.ENDC}

Commands:
  gobuster dir <url>           - Directory brute-force (gobuster)
  gobuster dns <domain>        - DNS subdomain fuzzing
  gobuster vhost <url>         - Virtual host discovery
  ffuf <url/FUZZ>              - Fast web fuzzer (use FUZZ as placeholder)
  ferox <url>                  - Recursive content discovery
  fuzz <url>                   - Built-in Python fuzzer (no external tools)
  vhost <domain> <ip>          - Virtual host enumeration
  wordlists                    - Show available/configured wordlists
  tools                        - Check tool availability
  results                      - Browse saved results

Type 'back' to return to main menu.
"""

    # ── tools ─────────────────────────────────────────────────────────────

    def do_tools(self, _arg: str) -> None:
        """Check which fuzzing tools are installed."""
        tools = ['gobuster', 'ffuf', 'feroxbuster', 'wfuzz']
        self._print_header("Fuzzer Tool Availability")
        for t in tools:
            found  = shutil.which(t) is not None
            color  = Colors.OKGREEN if found else Colors.FAIL
            status = "✓ installed" if found else "✗ not found"
            print(f"  {color}{t:<20} {status}{Colors.ENDC}")

        wl = self.config['wordlist']
        wl_exists = Path(wl).exists()
        color = Colors.OKGREEN if wl_exists else Colors.WARNING
        print(f"\n  {color}Wordlist: {wl}  ({'✓ exists' if wl_exists else '⚠ not found'}){Colors.ENDC}")
        print()

    # ── gobuster ──────────────────────────────────────────────────────────

    def do_gobuster(self, arg: str) -> None:
        """
        Run gobuster directory/DNS/vhost scan.

        Usage:
            gobuster dir   <url>           - Directory enumeration
            gobuster dns   <domain>        - Subdomain enumeration
            gobuster vhost <url>           - Virtual host discovery

        Examples:
            gobuster dir http://10.10.10.1/
            gobuster dns example.com
        """
        parts = arg.strip().split(maxsplit=1)
        if len(parts) < 2:
            self._print_error("Usage: gobuster <dir|dns|vhost> <target>")
            return

        mode, target = parts[0].lower(), parts[1].strip()

        if not shutil.which('gobuster'):
            self._print_error(
                "gobuster not found. Install with:\n"
                "  apt-get install gobuster  or  go install github.com/OJ/gobuster/v3@latest"
            )
            return

        # Scope check (extract host from URL)
        host = self._extract_host(target)
        if not self._require_scope(host):
            return

        wl  = self.config['wordlist']
        if not Path(wl).exists():
            self._print_error(f"Wordlist not found: {wl}\nSet with: config wordlist <path>")
            return

        out_file = self.results_dir / f'gobuster_{mode}_{host}_{self._timestamp()}.txt'
        threads  = str(self.config['threads'])

        if mode == 'dir':
            ext = self.config['extensions']
            codes = self.config['status_codes']
            cmd = [
                'gobuster', 'dir',
                '-u', target,
                '-w', wl,
                '-t', threads,
                '-s', codes,
                '-x', ext,
                '-o', str(out_file),
                '--no-error',
            ]
            if self.config['follow_redirects']:
                cmd.append('-r')

        elif mode == 'dns':
            cmd = [
                'gobuster', 'dns',
                '-d', target,
                '-w', wl,
                '-t', threads,
                '-o', str(out_file),
            ]
        elif mode == 'vhost':
            cmd = [
                'gobuster', 'vhost',
                '-u', target,
                '-w', wl,
                '-t', threads,
                '-o', str(out_file),
            ]
        else:
            self._print_error(f"Unknown mode '{mode}'. Use: dir, dns, vhost")
            return

        self._print_info(f"Running gobuster {mode} on {target}...")
        self._audit('gobuster', f"{mode} {target}")
        self._run_tool(cmd, "gobuster")
        self._print_info(f"Results saved: {out_file}")

    # ── ffuf ──────────────────────────────────────────────────────────────

    def do_ffuf(self, arg: str) -> None:
        """
        Run ffuf (fast web fuzzer).

        Usage: ffuf <url-with-FUZZ>

        The word FUZZ is replaced with each wordlist entry.

        Examples:
            ffuf http://10.10.10.1/FUZZ
            ffuf http://10.10.10.1/index.php?id=FUZZ
            ffuf http://10.10.10.1/FUZZ.php
        """
        url = arg.strip()
        if not url:
            self._print_error("Usage: ffuf <url-with-FUZZ>")
            return
        if 'FUZZ' not in url:
            self._print_warning("'FUZZ' keyword not found in URL. Appending /FUZZ")
            url = url.rstrip('/') + '/FUZZ'

        if not shutil.which('ffuf'):
            self._print_error(
                "ffuf not found. Install from:\n"
                "  apt-get install ffuf  or  go install github.com/ffuf/ffuf/v2@latest"
            )
            return

        host    = self._extract_host(url)
        if not self._require_scope(host):
            return

        wl = self.config['wordlist']
        if not Path(wl).exists():
            self._print_error(f"Wordlist not found: {wl}")
            return

        out_file = self.results_dir / f'ffuf_{host}_{self._timestamp()}.json'
        cmd = [
            'ffuf',
            '-u', url,
            '-w', wl,
            '-t', str(self.config['threads']),
            '-mc', self.config['status_codes'],
            '-o', str(out_file),
            '-of', 'json',
            '-H', f"User-Agent: {self.config['user_agent']}",
        ]
        if self.config['follow_redirects']:
            cmd.append('-r')

        self._print_info(f"Running ffuf on {url}...")
        self._audit('ffuf', url)
        self._run_tool(cmd, "ffuf")

    # ── feroxbuster ───────────────────────────────────────────────────────

    def do_ferox(self, arg: str) -> None:
        """
        Run feroxbuster for recursive content discovery.

        Usage: ferox <url>

        Note: feroxbuster is recursive by default — it follows discovered paths.
        """
        url = arg.strip()
        if not url:
            self._print_error("Usage: ferox <url>")
            return

        if not shutil.which('feroxbuster'):
            self._print_error(
                "feroxbuster not found. Install from:\n"
                "  curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash\n"
                "  or: apt-get install feroxbuster"
            )
            return

        host = self._extract_host(url)
        if not self._require_scope(host):
            return

        wl = self.config['wordlist']
        if not Path(wl).exists():
            self._print_error(f"Wordlist not found: {wl}")
            return

        out_file = self.results_dir / f'ferox_{host}_{self._timestamp()}.txt'
        cmd = [
            'feroxbuster',
            '-u', url,
            '-w', wl,
            '-t', str(self.config['threads']),
            '-s', self.config['status_codes'].replace(',', ' '),
            '-x', self.config['extensions'],
            '-o', str(out_file),
        ]

        self._print_info(f"Running feroxbuster on {url}  (recursive)...")
        self._audit('feroxbuster', url)
        self._run_tool(cmd, "feroxbuster")

    # ── built-in Python fuzzer ────────────────────────────────────────────

    def do_fuzz(self, arg: str) -> None:
        """
        Built-in Python directory fuzzer — no external tools required.

        Usage: fuzz <url> [wordlist]

        Examples:
            fuzz http://10.10.10.1/
            fuzz http://10.10.10.1/ /path/to/wordlist.txt
        """
        parts = arg.strip().split(maxsplit=1)
        if not parts:
            self._print_error("Usage: fuzz <url> [wordlist]")
            return

        base_url  = parts[0].rstrip('/')
        wl_path   = parts[1] if len(parts) > 1 else self.config['wordlist']

        if not Path(wl_path).exists():
            self._print_error(f"Wordlist not found: {wl_path}")
            return

        host = self._extract_host(base_url)
        if not self._require_scope(host):
            return

        words = Path(wl_path).read_text(errors='ignore').splitlines()
        words = [w.strip() for w in words if w.strip() and not w.startswith('#')]

        self._print_info(
            f"Fuzzing {base_url}  ({len(words)} words, "
            f"threads: {self.config['threads']})"
        )
        self._audit('fuzz', f"{base_url} wordlist={wl_path}")

        target_codes = {int(c) for c in self.config['status_codes'].split(',')}
        session      = self._build_session()
        found        = []
        lock         = threading.Lock()
        counter      = [0]
        total        = len(words)

        def check(word: str):
            url = f"{base_url}/{word}"
            try:
                resp = session.get(url, timeout=10, allow_redirects=self.config['follow_redirects'])
                counter[0] += 1
                if resp.status_code in target_codes:
                    size = len(resp.content)
                    with lock:
                        found.append((resp.status_code, size, url))
                        color = Colors.OKGREEN if resp.status_code == 200 else Colors.WARNING
                        print(f"  {color}[{resp.status_code}]{Colors.ENDC}  {size:>8} B  {url}")
            except requests.exceptions.ConnectionError:
                pass
            except requests.exceptions.RequestException:
                pass

        # Thread pool
        threads_list = []
        chunk  = max(1, len(words) // self.config['threads'])
        start  = time.time()

        from concurrent.futures import ThreadPoolExecutor, as_completed
        print()
        with ThreadPoolExecutor(max_workers=self.config['threads']) as ex:
            futures = [ex.submit(check, w) for w in words]
            for _ in as_completed(futures):
                pass

        elapsed = time.time() - start
        print()
        self._print_success(
            f"Done. {len(found)} paths found in {elapsed:.1f}s  "
            f"({len(words)/elapsed:.0f} req/s)"
        )

        if found and self.config['save_results']:
            lines = [f"[{code}] {size}B  {url}" for code, size, url in found]
            out   = self._save_output('\n'.join(lines), prefix=f'fuzz_{host}', ext='txt')
            self._print_info(f"Saved: {out}")

    # ── vhost ─────────────────────────────────────────────────────────────

    def do_vhost(self, arg: str) -> None:
        """
        Virtual host enumeration.

        Usage: vhost <domain> <ip>

        Tests subdomains of <domain> against <ip> via Host header manipulation.
        Uses gobuster vhost if available, otherwise built-in method.
        """
        parts = arg.strip().split()
        if len(parts) < 2:
            self._print_error("Usage: vhost <domain> <ip>")
            return

        domain, ip = parts[0], parts[1]
        if not self._require_scope(ip):
            return

        wl = self.config['wordlist']
        if not Path(wl).exists():
            self._print_error(f"Wordlist not found: {wl}")
            return

        if shutil.which('gobuster'):
            self._print_info(f"Running gobuster vhost: {domain} → {ip}")
            cmd = [
                'gobuster', 'vhost',
                '-u', f'http://{ip}',
                '-w', wl,
                '-t', str(self.config['threads']),
                '--append-domain',
                '-r',
            ]
            self._audit('vhost', f"{domain} {ip}")
            self._run_tool(cmd, "gobuster vhost")
        else:
            # Built-in vhost fuzzer
            self._print_info(f"Built-in vhost scan: {domain} @ {ip}")
            self._audit('vhost', f"{domain} {ip} (built-in)")
            session  = self._build_session()
            subwords = Path(wl).read_text(errors='ignore').splitlines()[:500]
            found    = []

            for word in subwords:
                word = word.strip()
                if not word:
                    continue
                host_header = f"{word}.{domain}"
                try:
                    resp = session.get(
                        f"http://{ip}/",
                        headers={'Host': host_header},
                        timeout=5,
                        allow_redirects=False
                    )
                    if resp.status_code not in (400, 404, 500):
                        found.append((resp.status_code, host_header))
                        print(f"  {Colors.OKGREEN}[{resp.status_code}]{Colors.ENDC}  {host_header}")
                except Exception:
                    pass

            self._print_success(f"vhost scan complete. {len(found)} results found.")

    # ── wordlists ─────────────────────────────────────────────────────────

    def do_wordlists(self, _arg: str) -> None:
        """Show available wordlists."""
        self._print_header("Wordlist Status")
        current = self.config['wordlist']
        for wl in DEFAULT_WORDLISTS:
            exists = Path(wl).exists()
            color  = Colors.OKGREEN if exists else Colors.FAIL
            marker = " ◀ active" if wl == current else ""
            print(f"  {color}{'✓' if exists else '✗'}{Colors.ENDC}  {wl}{marker}")

        # SecLists detection
        seclists = Path('/usr/share/seclists')
        if seclists.exists():
            self._print_success(f"SecLists detected at {seclists}")
        else:
            self._print_info("SecLists not found. Install: apt-get install seclists")
        print()

    # ── results ───────────────────────────────────────────────────────────

    def do_results(self, arg: str) -> None:
        """List saved fuzzer results. Usage: results [filter]"""
        files = sorted(self.results_dir.iterdir()) if self.results_dir.exists() else []
        if arg.strip():
            files = [f for f in files if arg.strip() in f.name]
        if not files:
            self._print_info("No results found.")
            return
        self._print_header(f"Fuzzer Results ({len(files)} files)")
        for f in files:
            size = f.stat().st_size
            ts   = datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M')
            print(f"  {Colors.OKCYAN}{f.name:<60}{Colors.ENDC}  {size:>8,} B  {ts}")
        print()

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _extract_host(url: str) -> str:
        """Pull the hostname/IP from a URL or raw target string."""
        url = url.strip()
        if url.startswith('http'):
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            return parsed.hostname or url
        return url.split('/')[0].split(':')[0]

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers['User-Agent'] = self.config['user_agent']
        retry = Retry(total=2, backoff_factor=0.3)
        session.mount('http://', HTTPAdapter(max_retries=retry))
        session.mount('https://', HTTPAdapter(max_retries=retry))
        return session

    def _run_tool(self, cmd: list, tool_name: str) -> None:
        """Run a subprocess tool with live output streaming."""
        try:
            self._print_info(f"Command: {' '.join(cmd)}")
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            for line in proc.stdout:
                print(line, end='')
            proc.wait()
            rc = proc.returncode
            if rc == 0:
                self._print_success(f"{tool_name} finished successfully.")
            else:
                self._print_warning(f"{tool_name} exited with code {rc}.")

        except FileNotFoundError:
            self._print_error(f"{tool_name} binary not found.")
        except subprocess.TimeoutExpired:
            self._print_error(f"{tool_name} timed out.")
        except Exception as e:
            self._print_error(f"{tool_name} error: {e}")
