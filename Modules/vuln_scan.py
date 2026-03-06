"""
Vulnerability Scanning Module
Advanced vulnerability assessment using multiple scanning tools.
"""

import cmd
import subprocess
import logging
import re
import json
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime
import xml.etree.ElementTree as ET


class VulnerabilityScanningModule(cmd.Cmd):
    """
    Advanced vulnerability scanning module with multiple tools and scan types.
    
    Features:
    - Multiple scanning tools (Nikto, Nmap NSE, Custom scripts)
    - Web application scanning
    - Network vulnerability scanning
    - SSL/TLS security testing
    - CVE identification
    - Scan profiles and templates
    - Report generation
    - Scan history and comparison
    - Output parsing and analysis
    """
    
    prompt = '(vulnscan) '
    intro = '''
╔══════════════════════════════════════════════════════════════╗
║           Vulnerability Scanning Module                       ║
╚══════════════════════════════════════════════════════════════╝

Quick Scans:
  scan <target>           - Quick vulnerability scan
  web <url>               - Web application scan (Nikto)
  network <target>        - Network vulnerability scan (Nmap NSE)
  ssl <target>            - SSL/TLS security test
  
Nikto Scans:
  nikto <url>             - Full Nikto scan
  nikto_quick <url>       - Quick Nikto scan
  nikto_tuning <url>      - Custom tuning options
  
Nmap Vulnerability Scans:
  nmap_vuln <target>      - Nmap vulnerability scripts
  nmap_exploit <target>   - Check for known exploits
  nmap_malware <target>   - Malware detection scan
  
Specialized Scans:
  cms_scan <url>          - CMS detection and scanning
  directory_scan <url>    - Directory enumeration
  headers <url>           - Security headers analysis
  ports <target>          - Common vulnerable ports
  
Management:
  results                 - View scan history
  analyze <scan_id>       - Analyze scan results
  compare <id1> <id2>     - Compare two scans
  export <scan_id>        - Export scan results
  profiles                - View scan profiles
  config                  - Configure settings

Type 'help <command>' for detailed usage.
Type 'back' or 'exit' to return to main menu.
'''
    
    def __init__(self):
        """Initialize the vulnerability scanning module."""
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configuration
        self.config = {
            'nikto_path': 'nikto',
            'nmap_path': 'nmap',
            'timeout': 3600,
            'output_format': 'text',
            'save_output': True,
            'verbose': True,
            'user_agent': 'Mozilla/5.0 (compatible; VulnScanner/1.0)',
            'threads': 4,
            'max_redirects': 3
        }
        
        # Output directory
        self.output_dir = Path.home() / '.pentest_toolkit' / 'vuln_scans'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Scan history
        self.scan_history = []
        self._load_history()
        
        # Scan profiles
        self.profiles = {
            'quick': {
                'description': 'Quick scan of common vulnerabilities',
                'options': '-Tuning 1234'
            },
            'full': {
                'description': 'Comprehensive vulnerability scan',
                'options': '-Tuning 123456789'
            },
            'intrusive': {
                'description': 'Aggressive scan including dangerous tests',
                'options': '-Tuning 123456789x'
            },
            'passive': {
                'description': 'Passive reconnaissance only',
                'options': '-Tuning 12'
            }
        }
        
        # Common vulnerable ports
        self.vuln_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
        
        # Check tool availability
        self.tools_available = self._check_tools()
    
    # ===== Quick Scan Commands =====
    
    def do_scan(self, arg: str) -> None:
        """
        Quick vulnerability scan (auto-detect type).
        
        Usage: scan <target>
        
        Auto-detects if target is URL (web scan) or IP/host (network scan).
        
        Examples:
            scan http://example.com
            scan 192.168.1.1
            scan example.com
        """
        if not arg:
            print("Usage: scan <target>")
            return
        
        target = arg.strip()
        
        # Auto-detect scan type
        if target.startswith('http://') or target.startswith('https://'):
            print(f"ℹ Detected web target, running web application scan...")
            self.do_web(target)
        else:
            print(f"ℹ Detected network target, running network vulnerability scan...")
            self.do_network(target)
    
    def do_web(self, arg: str) -> None:
        """
        Web application vulnerability scan.
        
        Usage: web <url>
        
        Performs comprehensive web app scanning using Nikto.
        
        Examples:
            web http://example.com
            web https://example.com:8443
        """
        if not arg:
            print("Usage: web <url>")
            return
        
        if not self.tools_available.get('nikto'):
            print("✗ Error: Nikto not available")
            print("  Install with: sudo apt-get install nikto")
            return
        
        url = arg.strip()
        self._run_nikto_scan(url, profile='full')
    
    def do_network(self, arg: str) -> None:
        """
        Network vulnerability scan using Nmap NSE scripts.
        
        Usage: network <target>
        
        Runs Nmap vulnerability detection scripts.
        
        Examples:
            network 192.168.1.1
            network example.com
        """
        if not arg:
            print("Usage: network <target>")
            return
        
        if not self.tools_available.get('nmap'):
            print("✗ Error: Nmap not available")
            print("  Install with: sudo apt-get install nmap")
            return
        
        target = arg.strip()
        self._run_nmap_vuln_scan(target, script_category='vuln')
    
    def do_ssl(self, arg: str) -> None:
        """
        SSL/TLS security testing.
        
        Usage: ssl <target>
        
        Tests SSL/TLS configuration and certificates.
        
        Examples:
            ssl example.com
            ssl 192.168.1.1:443
        """
        if not arg:
            print("Usage: ssl <target>")
            return
        
        target = arg.strip()
        
        # Ensure port is specified
        if ':' not in target:
            target = f"{target}:443"
        
        self._run_ssl_scan(target)
    
    # ===== Nikto Scans =====
    
    def do_nikto(self, arg: str) -> None:
        """
        Full Nikto web server scan.
        
        Usage: nikto <url> [options]
        
        Options: Use Nikto options directly (e.g., -Tuning, -evasion)
        
        Examples:
            nikto http://example.com
            nikto https://example.com -Tuning 123
            nikto http://example.com -evasion 1
        """
        if not arg:
            print("Usage: nikto <url> [options]")
            return
        
        if not self.tools_available.get('nikto'):
            print("✗ Error: Nikto not available")
            return
        
        parts = arg.split(maxsplit=1)
        url = parts[0]
        options = parts[1] if len(parts) > 1 else ''
        
        self._run_nikto_scan(url, custom_options=options)
    
    def do_nikto_quick(self, arg: str) -> None:
        """
        Quick Nikto scan (common vulnerabilities only).
        
        Usage: nikto_quick <url>
        
        Example:
            nikto_quick http://example.com
        """
        if not arg:
            print("Usage: nikto_quick <url>")
            return
        
        self._run_nikto_scan(arg.strip(), profile='quick')
    
    def do_nikto_tuning(self, arg: str) -> None:
        """
        Nikto scan with custom tuning options.
        
        Usage: nikto_tuning <url> <tuning_options>
        
        Tuning options:
            1 - Interesting File / Seen in logs
            2 - Misconfiguration / Default File
            3 - Information Disclosure
            4 - Injection (XSS/Script/HTML)
            5 - Remote File Retrieval - Inside Web Root
            6 - Denial of Service
            7 - Remote File Retrieval - Server Wide
            8 - Command Execution / Remote Shell
            9 - SQL Injection
            0 - File Upload
            a - Authentication Bypass
            b - Software Identification
            c - Remote Source Inclusion
            x - Reverse Tuning Options (i.e., include all except specified)
        
        Examples:
            nikto_tuning http://example.com 123
            nikto_tuning http://example.com 49
        """
        parts = arg.split()
        
        if len(parts) != 2:
            print("Usage: nikto_tuning <url> <tuning_options>")
            return
        
        url, tuning = parts
        self._run_nikto_scan(url, custom_options=f'-Tuning {tuning}')
    
    # ===== Nmap Vulnerability Scans =====
    
    def do_nmap_vuln(self, arg: str) -> None:
        """
        Nmap vulnerability scanning scripts.
        
        Usage: nmap_vuln <target>
        
        Runs Nmap NSE vuln category scripts.
        
        Example:
            nmap_vuln 192.168.1.1
        """
        if not arg:
            print("Usage: nmap_vuln <target>")
            return
        
        self._run_nmap_vuln_scan(arg.strip(), script_category='vuln')
    
    def do_nmap_exploit(self, arg: str) -> None:
        """
        Check for known exploits using Nmap.
        
        Usage: nmap_exploit <target>
        
        Runs Nmap exploit detection scripts.
        
        Example:
            nmap_exploit 192.168.1.1
        """
        if not arg:
            print("Usage: nmap_exploit <target>")
            return
        
        self._run_nmap_vuln_scan(arg.strip(), script_category='exploit')
    
    def do_nmap_malware(self, arg: str) -> None:
        """
        Malware detection scan using Nmap.
        
        Usage: nmap_malware <target>
        
        Checks for signs of malware/backdoors.
        
        Example:
            nmap_malware 192.168.1.1
        """
        if not arg:
            print("Usage: nmap_malware <target>")
            return
        
        self._run_nmap_vuln_scan(arg.strip(), script_category='malware')
    
    # ===== Specialized Scans =====
    
    def do_cms_scan(self, arg: str) -> None:
        """
        CMS (WordPress, Joomla, Drupal) detection and scanning.
        
        Usage: cms_scan <url>
        
        Detects and scans common CMS platforms.
        
        Example:
            cms_scan http://example.com
        """
        if not arg:
            print("Usage: cms_scan <url>")
            return
        
        url = arg.strip()
        
        print(f"\n{'='*70}")
        print(f"CMS Detection and Scanning")
        print(f"{'='*70}\n")
        print(f"Target: {url}")
        print(f"\nScanning for common CMS platforms...")
        
        # Use Nikto with CMS-focused tuning
        self._run_nikto_scan(url, custom_options='-Tuning b')
    
    def do_directory_scan(self, arg: str) -> None:
        """
        Directory and file enumeration.
        
        Usage: directory_scan <url>
        
        Scans for common directories and files.
        
        Example:
            directory_scan http://example.com
        """
        if not arg:
            print("Usage: directory_scan <url>")
            return
        
        url = arg.strip()
        
        # Use Nikto with file/directory focus
        self._run_nikto_scan(url, custom_options='-Tuning 12')
    
    def do_headers(self, arg: str) -> None:
        """
        Analyze HTTP security headers.
        
        Usage: headers <url>
        
        Checks for security-related HTTP headers.
        
        Example:
            headers http://example.com
        """
        if not arg:
            print("Usage: headers <url>")
            return
        
        url = arg.strip()
        
        try:
            import requests
            
            print(f"\n{'='*70}")
            print(f"HTTP Security Headers Analysis")
            print(f"{'='*70}\n")
            print(f"Target: {url}\n")
            
            response = requests.get(url, timeout=10, verify=False)
            headers = response.headers
            
            # Security headers to check
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'Content-Security-Policy': 'CSP',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'X-XSS-Protection': 'XSS Protection',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy'
            }
            
            print(f"{'Header':<35} {'Status':<15} {'Value':<40}")
            print("-" * 90)
            
            for header, description in security_headers.items():
                if header in headers:
                    status = "✓ Present"
                    value = headers[header][:37] + '...' if len(headers[header]) > 40 else headers[header]
                else:
                    status = "✗ Missing"
                    value = "Not set"
                
                print(f"{description:<35} {status:<15} {value:<40}")
            
            print(f"\n{'='*70}\n")
            
        except ImportError:
            print("✗ Error: requests library not available")
            print("  Install with: pip install requests")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def do_ports(self, arg: str) -> None:
        """
        Scan common vulnerable ports.
        
        Usage: ports <target>
        
        Scans common ports known to have vulnerabilities.
        
        Example:
            ports 192.168.1.1
        """
        if not arg:
            print("Usage: ports <target>")
            return
        
        target = arg.strip()
        port_list = ','.join(str(p) for p in self.vuln_ports.keys())
        
        print(f"\n{'='*70}")
        print(f"Common Vulnerable Ports Scan")
        print(f"{'='*70}\n")
        print(f"Target: {target}")
        print(f"Ports: {len(self.vuln_ports)} common vulnerable services\n")
        
        cmd = [
            self.config['nmap_path'],
            '-sV',
            '-p', port_list,
            '--script', 'vuln',
            target
        ]
        
        self._execute_scan(cmd, 'nmap', 'ports', target)
    
    # ===== Scan Execution Helpers =====
    
    def _run_nikto_scan(self, url: str, profile: Optional[str] = None, 
                       custom_options: str = '') -> None:
        """Execute Nikto scan."""
        # Generate output filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_url = re.sub(r'[^\w\.-]', '_', url)
        output_file = self.output_dir / f'nikto_{safe_url}_{timestamp}.txt'
        
        # Build command
        cmd = [self.config['nikto_path'], '-h', url]
        
        # Add profile options
        if profile and profile in self.profiles:
            cmd.extend(self.profiles[profile]['options'].split())
        
        # Add custom options
        if custom_options:
            cmd.extend(custom_options.split())
        
        # Add output
        if self.config['save_output']:
            cmd.extend(['-output', str(output_file)])
        
        # Add other options
        cmd.extend(['-useragent', self.config['user_agent']])
        
        print(f"\n{'='*70}")
        print(f"Nikto Web Vulnerability Scan")
        print(f"{'='*70}\n")
        print(f"Target:  {url}")
        if profile:
            print(f"Profile: {profile}")
        print(f"Output:  {output_file}")
        print(f"\nScanning...\n")
        print(f"{'='*70}\n")
        
        self._execute_scan(cmd, 'nikto', 'web', url, output_file)
    
    def _run_nmap_vuln_scan(self, target: str, script_category: str) -> None:
        """Execute Nmap vulnerability scan."""
        # Generate output filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = re.sub(r'[^\w\.-]', '_', target)
        output_file = self.output_dir / f'nmap_{script_category}_{safe_target}_{timestamp}.xml'
        
        # Build command
        cmd = [
            self.config['nmap_path'],
            '-sV',
            '--script', script_category,
            target
        ]
        
        if self.config['save_output']:
            cmd.extend(['-oX', str(output_file)])
        
        if self.config['verbose']:
            cmd.append('-v')
        
        print(f"\n{'='*70}")
        print(f"Nmap Vulnerability Scan ({script_category})")
        print(f"{'='*70}\n")
        print(f"Target:  {target}")
        print(f"Scripts: {script_category}")
        print(f"Output:  {output_file}")
        print(f"\nScanning...\n")
        print(f"{'='*70}\n")
        
        self._execute_scan(cmd, 'nmap', script_category, target, output_file)
    
    def _run_ssl_scan(self, target: str) -> None:
        """Execute SSL/TLS scan."""
        cmd = [
            self.config['nmap_path'],
            '-sV',
            '--script', 'ssl-enum-ciphers,ssl-cert,ssl-known-key',
            '-p', target.split(':')[1] if ':' in target else '443',
            target.split(':')[0]
        ]
        
        print(f"\n{'='*70}")
        print(f"SSL/TLS Security Scan")
        print(f"{'='*70}\n")
        print(f"Target: {target}\n")
        print(f"Scanning...\n")
        print(f"{'='*70}\n")
        
        self._execute_scan(cmd, 'nmap', 'ssl', target)
    
    def _execute_scan(self, cmd: List[str], tool: str, scan_type: str, 
                     target: str, output_file: Optional[Path] = None) -> None:
        """Execute vulnerability scan and manage results."""
        cmd_str = ' '.join(cmd)
        self.logger.info(f"Executing: {cmd_str}")
        
        start_time = datetime.now()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=False,  # Show output in real-time
                timeout=self.config['timeout']
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            if result.returncode == 0:
                print(f"\n{'='*70}")
                print(f"✓ Scan completed in {duration:.2f} seconds")
                print(f"{'='*70}\n")
                
                # Record scan
                scan_record = {
                    'id': len(self.scan_history) + 1,
                    'timestamp': start_time.isoformat(),
                    'tool': tool,
                    'scan_type': scan_type,
                    'target': target,
                    'command': cmd_str,
                    'duration': duration,
                    'output_file': str(output_file) if output_file else None,
                    'status': 'completed'
                }
                
                self.scan_history.append(scan_record)
                self._save_history()
                
                if output_file and output_file.exists():
                    print(f"Results saved to: {output_file}")
                
            else:
                print(f"\n✗ Scan failed with exit code {result.returncode}")
                
        except subprocess.TimeoutExpired:
            print(f"\n✗ Scan timed out after {self.config['timeout']} seconds")
        except KeyboardInterrupt:
            print(f"\n⚠ Scan cancelled by user")
        except Exception as e:
            print(f"\n✗ Error: {e}")
            self.logger.error(f"Scan error: {e}", exc_info=True)
    
    # ===== Results Management =====
    
    def do_results(self, arg: str) -> None:
        """
        View scan history.
        
        Usage: results [count]
        
        Example:
            results     - Show last 10 scans
            results 20  - Show last 20 scans
        """
        count = 10
        if arg:
            try:
                count = int(arg)
            except ValueError:
                print("Error: Count must be an integer")
                return
        
        if not self.scan_history:
            print("No scan history available")
            return
        
        recent = self.scan_history[-count:]
        
        print(f"\n{'='*90}")
        print(f"Scan History (last {len(recent)})")
        print(f"{'='*90}")
        print(f"\n{'ID':<5} {'Date/Time':<20} {'Tool':<10} {'Type':<15} {'Target':<30}")
        print("-" * 90)
        
        for scan in reversed(recent):
            scan_id = scan['id']
            timestamp = datetime.fromisoformat(scan['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            tool = scan['tool']
            scan_type = scan['scan_type']
            target = scan['target'][:27] + '...' if len(scan['target']) > 30 else scan['target']
            
            print(f"{scan_id:<5} {timestamp:<20} {tool:<10} {scan_type:<15} {target:<30}")
        
        print(f"\n{'='*90}\n")
    
    def do_profiles(self, arg: str) -> None:
        """
        View available scan profiles.
        
        Usage: profiles
        """
        print(f"\n{'='*70}")
        print("Available Scan Profiles")
        print(f"{'='*70}\n")
        
        for name, info in self.profiles.items():
            print(f"• {name}")
            print(f"  Description: {info['description']}")
            print(f"  Options:     {info['options']}")
            print()
        
        print(f"{'='*70}\n")
    
    def do_config(self, arg: str) -> None:
        """
        Configure module settings.
        
        Usage: config [key] [value]
               config show
        
        Examples:
            config show
            config timeout 7200
            config verbose true
        """
        args = arg.split(maxsplit=1)
        
        if not args or args[0] == 'show':
            print(f"\n{'='*70}")
            print("Current Configuration")
            print(f"{'='*70}\n")
            for key, value in sorted(self.config.items()):
                print(f"  {key:.<30} {value}")
            print()
            return
        
        if len(args) < 2:
            print("Usage: config [key] [value] | config show")
            return
        
        key, value = args[0], args[1]
        
        if key not in self.config:
            print(f"✗ Error: Unknown setting '{key}'")
            return
        
        # Type conversion
        if isinstance(self.config[key], bool):
            value = value.lower() in ['true', '1', 'yes', 'on']
        elif isinstance(self.config[key], int):
            try:
                value = int(value)
            except ValueError:
                print(f"✗ Error: '{key}' must be an integer")
                return
        
        self.config[key] = value
        print(f"✓ Set {key} = {value}")
    
    # ===== Helper Methods =====
    
    def _check_tools(self) -> Dict[str, bool]:
        """Check availability of scanning tools."""
        tools = {}
        
        # Check Nikto
        try:
            subprocess.run(
                ['nikto', '-Version'],
                capture_output=True,
                timeout=5
            )
            tools['nikto'] = True
        except:
            tools['nikto'] = False
        
        # Check Nmap
        try:
            subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                timeout=5
            )
            tools['nmap'] = True
        except:
            tools['nmap'] = False
        
        return tools
    
    def _load_history(self) -> None:
        """Load scan history from file."""
        history_file = self.output_dir / 'scan_history.json'
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    self.scan_history = json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading history: {e}")
    
    def _save_history(self) -> None:
        """Save scan history to file."""
        history_file = self.output_dir / 'scan_history.json'
        try:
            with open(history_file, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving history: {e}")
    
    # ===== Exit Commands =====
    
    def do_back(self, arg: str) -> bool:
        """Return to main menu."""
        print("Exiting Vulnerability Scanning Module.")
        self.logger.info("Vulnerability scanning module exited")
        return True
    
    def do_exit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    def do_quit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    # ===== Tab Completion =====
    
    def complete_config(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for config command."""
        options = ['show'] + list(self.config.keys())
        return [opt for opt in options if opt.startswith(text)]
    
    def emptyline(self) -> None:
        """Do nothing on empty line."""
        pass
    
    def default(self, line: str) -> None:
        """Handle unknown commands."""
        print(f"✗ Unknown command: {line}")
        print("Type 'help' for available commands")


# ===== Standalone Testing =====

def main():
    """Run module in standalone mode for testing."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("Running Vulnerability Scanning Module in test mode...")
    VulnerabilityScanningModule().cmdloop()


if __name__ == '__main__':
    main()
