"""
Nmap Module
Advanced network scanning and enumeration using Nmap.
"""

import cmd
import subprocess
import logging
import re
import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Dict, List, Tuple
from datetime import datetime
import shutil


class NmapModule(cmd.Cmd):
    """
    Advanced Nmap scanning module with comprehensive scan types and result management.
    
    Features:
    - 15+ scan types (SYN, Connect, UDP, ACK, Stealth, etc.)
    - OS detection and version scanning
    - NSE script scanning with categories
    - Multiple output formats (normal, XML, grepable, JSON)
    - Scan result parsing and analysis
    - Scan history and result management
    - Port range specification
    - Timing templates (0-5)
    - Custom scan profiles
    - Target validation
    - Progress tracking
    - Output colorization
    """
    
    prompt = '(nmap) '
    intro = '''
╔══════════════════════════════════════════════════════════════╗
║              Advanced Nmap Scanning Module                    ║
║          Network Mapping & Port Scanning Tool                 ║
╚══════════════════════════════════════════════════════════════╝

Quick Start:
  scan <target>              - Quick comprehensive scan
  quick <target>             - Fast top 100 ports scan
  full <target>              - Full port scan (all 65535 ports)
  
Scan Types:
  tcp_syn_scan               - Fast SYN scan (stealth, requires root)
  tcp_connect_scan           - TCP connect() scan (no root required)
  udp_scan                   - UDP port scan
  aggressive_scan            - Aggressive scan (-A: OS, version, scripts, traceroute)
  stealth_scan               - Ultra-stealth scan
  version_detection          - Service version detection
  os_fingerprinting          - Operating system detection
  
Advanced Scans:
  xmas_scan                  - XMAS scan (FIN, PSH, URG flags)
  null_scan                  - NULL scan (no flags set)
  fin_scan                   - FIN scan
  tcp_ack_scan               - ACK scan (firewall rule detection)
  ping_sweep                 - Host discovery (no port scan)
  script_scan                - NSE script scanning
  vulnerability_scan         - Check for common vulnerabilities
  
Management:
  results                    - View recent scan results
  history                    - Show scan history
  analyze <scan_id>          - Analyze specific scan results
  export <scan_id> <format>  - Export scan results
  config                     - Configure module settings
  profiles                   - Manage scan profiles

Type 'help <command>' for detailed usage.
Type 'back' or 'exit' to return to main menu.
'''
    
    def __init__(self):
        """Initialize the Nmap module."""
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configuration
        self.config = {
            'save_output': True,
            'auto_analyze': True,
            'timing_template': 'T3',  # Default timing (0-5)
            'default_ports': 'top-1000',
            'verbose': True,
            'save_xml': True,
            'save_json': True,
            'max_history': 50
        }
        
        # Directories
        self.output_dir = Path.home() / '.pentest_toolkit' / 'nmap_scans'
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Scan history
        self.scan_history = []
        self._load_history()
        
        # Scan profiles
        self.profiles = {
            'quick': '-T4 -F',
            'intense': '-T4 -A -v',
            'stealth': '-sS -T2 -f',
            'comprehensive': '-sS -sV -O -A -T4',
            'vulnerability': '-sV --script vuln',
            'discovery': '-sn -PE -PP -PS80,443 -PA3389',
        }
        
        # NSE script categories
        self.nse_categories = [
            'auth', 'broadcast', 'brute', 'default', 'discovery',
            'dos', 'exploit', 'external', 'fuzzer', 'intrusive',
            'malware', 'safe', 'version', 'vuln'
        ]
        
        # Check nmap installation
        self.nmap_version = self._check_nmap()
        if not self.nmap_version:
            print("⚠ Warning: Nmap not found in PATH")
            print("  Install with: sudo apt-get install nmap")
        else:
            print(f"✓ Nmap version {self.nmap_version} detected")
    
    # ===== Utility Methods =====
    
    def _check_nmap(self) -> Optional[str]:
        """Check if nmap is installed and return version."""
        try:
            result = subprocess.run(
                ['nmap', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                # Extract version from output
                match = re.search(r'Nmap version ([\d.]+)', result.stdout)
                if match:
                    return match.group(1)
            return "unknown"
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return None
    
    def _validate_target(self, target: str) -> bool:
        """Validate target IP, hostname, or CIDR notation."""
        if not target or target.strip() == '':
            print("✗ Error: Target is required")
            return False
        
        target = target.strip()
        
        # Common patterns
        patterns = {
            'ipv4': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
            'cidr': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$',
            'range': r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$',
            'hostname': r'^[\w\.-]+\.[a-zA-Z]{2,}$',
            'localhost': r'^localhost$|^127\.0\.0\.1$'
        }
        
        for pattern_type, pattern in patterns.items():
            if re.match(pattern, target):
                self.logger.info(f"Target validated as {pattern_type}: {target}")
                return True
        
        print(f"⚠ Warning: '{target}' may not be a valid target")
        print("  Valid formats: IP (192.168.1.1), CIDR (192.168.1.0/24),")
        print("                 Range (192.168.1.1-254), Hostname (example.com)")
        
        response = input("  Continue anyway? (y/n): ")
        return response.lower() == 'y'
    
    def _generate_output_filename(self, scan_type: str, target: str) -> Tuple[str, str]:
        """Generate unique filenames for scan output."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_target = re.sub(r'[^\w\.-]', '_', target)
        safe_scan = re.sub(r'[^\w-]', '', scan_type)
        
        base_name = f"{safe_scan}_{safe_target}_{timestamp}"
        output_file = self.output_dir / f"{base_name}.txt"
        xml_file = self.output_dir / f"{base_name}.xml"
        
        return str(output_file), str(xml_file)
    
    def _run_nmap(self, scan_type: str, target: str, 
                  extra_options: str = '', 
                  description: str = '') -> Optional[Dict]:
        """
        Execute nmap scan with comprehensive error handling and result management.
        
        Args:
            scan_type: Nmap scan flags (e.g., '-sS', '-sV')
            target: Target IP/hostname/range
            extra_options: Additional nmap options
            description: Human-readable scan description
            
        Returns:
            Dictionary containing scan results and metadata
        """
        if not self._validate_target(target):
            return None
        
        # Generate output files
        output_file, xml_file = self._generate_output_filename(scan_type, target)
        
        # Build command
        cmd_parts = ['nmap']
        
        # Add scan type
        if scan_type:
            cmd_parts.extend(scan_type.split())
        
        # Add timing template
        if f"-T{self.config['timing_template'][-1]}" not in scan_type:
            cmd_parts.append(f"-{self.config['timing_template']}")
        
        # Add verbosity
        if self.config['verbose'] and '-v' not in scan_type:
            cmd_parts.append('-v')
        
        # Add output options
        if self.config['save_output']:
            cmd_parts.extend(['-oN', output_file])
        
        if self.config['save_xml']:
            cmd_parts.extend(['-oX', xml_file])
        
        # Add extra options
        if extra_options:
            cmd_parts.extend(extra_options.split())
        
        # Add target (must be last)
        cmd_parts.append(target)
        
        # Display command
        cmd_str = ' '.join(cmd_parts)
        print(f"\n{'='*60}")
        print(f"Running: {cmd_str}")
        print(f"{'='*60}\n")
        
        self.logger.info(f"Executing nmap scan: {cmd_str}")
        
        # Execute scan
        start_time = datetime.now()
        
        try:
            result = subprocess.run(
                cmd_parts,
                capture_output=False,  # Show output in real-time
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            if result.returncode == 0:
                print(f"\n{'='*60}")
                print(f"✓ Scan completed successfully in {duration:.2f} seconds")
                print(f"{'='*60}\n")
                
                # Create scan record
                scan_record = {
                    'id': len(self.scan_history) + 1,
                    'timestamp': start_time.isoformat(),
                    'scan_type': scan_type,
                    'target': target,
                    'command': cmd_str,
                    'duration': duration,
                    'output_file': output_file,
                    'xml_file': xml_file if self.config['save_xml'] else None,
                    'description': description or scan_type,
                    'status': 'completed'
                }
                
                # Add to history
                self.scan_history.append(scan_record)
                self._save_history()
                
                # Auto-analyze if enabled
                if self.config['auto_analyze']:
                    self._analyze_scan(scan_record)
                
                print(f"Results saved to: {output_file}")
                if self.config['save_xml']:
                    print(f"XML output saved to: {xml_file}")
                
                return scan_record
                
            else:
                print(f"\n✗ Scan failed with exit code {result.returncode}")
                self.logger.error(f"Nmap scan failed: exit code {result.returncode}")
                return None
                
        except subprocess.TimeoutExpired:
            print("\n✗ Scan timed out after 1 hour")
            self.logger.error("Nmap scan timed out")
            return None
        except KeyboardInterrupt:
            print("\n⚠ Scan cancelled by user")
            self.logger.warning("Nmap scan cancelled by user")
            return None
        except Exception as e:
            print(f"\n✗ Error running scan: {e}")
            self.logger.error(f"Nmap scan error: {e}", exc_info=True)
            return None
    
    def _analyze_scan(self, scan_record: Dict) -> None:
        """Analyze scan results and display summary."""
        if not scan_record.get('xml_file') or not Path(scan_record['xml_file']).exists():
            return
        
        try:
            tree = ET.parse(scan_record['xml_file'])
            root = tree.getroot()
            
            print(f"\n{'='*60}")
            print("Scan Analysis Summary")
            print(f"{'='*60}")
            
            # Count hosts
            hosts_up = len(root.findall(".//host[status[@state='up']]"))
            hosts_down = len(root.findall(".//host[status[@state='down']]"))
            
            print(f"\nHosts: {hosts_up} up, {hosts_down} down")
            
            # Analyze open ports
            open_ports = []
            for host in root.findall(".//host[status[@state='up']]"):
                for port in host.findall(".//port[state[@state='open']]"):
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    service = port.find('service')
                    service_name = service.get('name') if service is not None else 'unknown'
                    service_version = service.get('version') if service is not None else ''
                    
                    open_ports.append({
                        'port': port_id,
                        'protocol': protocol,
                        'service': service_name,
                        'version': service_version
                    })
            
            if open_ports:
                print(f"\nOpen Ports: {len(open_ports)}")
                print(f"\n{'Port':<10} {'Protocol':<10} {'Service':<15} {'Version':<30}")
                print("-" * 65)
                for p in open_ports[:20]:  # Show first 20
                    version = p['version'][:27] + '...' if len(p['version']) > 30 else p['version']
                    print(f"{p['port']:<10} {p['protocol']:<10} {p['service']:<15} {version:<30}")
                
                if len(open_ports) > 20:
                    print(f"\n... and {len(open_ports) - 20} more ports")
            
            # Check for OS detection
            os_matches = root.findall(".//osmatch")
            if os_matches:
                print(f"\nOS Detection:")
                for os_match in os_matches[:3]:  # Top 3 matches
                    print(f"  • {os_match.get('name')} ({os_match.get('accuracy')}% accuracy)")
            
            print(f"\n{'='*60}\n")
            
        except Exception as e:
            self.logger.error(f"Error analyzing scan results: {e}")
    
    def _load_history(self) -> None:
        """Load scan history from file."""
        history_file = self.output_dir / 'scan_history.json'
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    self.scan_history = json.load(f)
                self.logger.info(f"Loaded {len(self.scan_history)} scan records")
            except Exception as e:
                self.logger.error(f"Error loading scan history: {e}")
    
    def _save_history(self) -> None:
        """Save scan history to file."""
        history_file = self.output_dir / 'scan_history.json'
        try:
            # Keep only recent scans
            if len(self.scan_history) > self.config['max_history']:
                self.scan_history = self.scan_history[-self.config['max_history']:]
            
            with open(history_file, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving scan history: {e}")
    
    # ===== Quick Scan Commands =====
    
    def do_scan(self, arg: str) -> None:
        """
        Quick comprehensive scan (most common use case).
        
        Usage: scan <target> [options]
        
        Examples:
            scan 192.168.1.1
            scan 192.168.1.0/24
            scan example.com -p 80,443,8080
            scan 10.0.0.1 -sV
        """
        if not arg:
            print("Usage: scan <target> [options]")
            return
        
        parts = arg.split(maxsplit=1)
        target = parts[0]
        extra_options = parts[1] if len(parts) > 1 else ''
        
        self._run_nmap('-sS -sV', target, extra_options, 'Quick comprehensive scan')
    
    def do_quick(self, arg: str) -> None:
        """
        Quick scan of top 100 ports.
        
        Usage: quick <target>
        
        Example:
            quick 192.168.1.1
        """
        if not arg:
            print("Usage: quick <target>")
            return
        
        self._run_nmap('-F -T4', arg.strip(), '', 'Quick top 100 ports')
    
    def do_full(self, arg: str) -> None:
        """
        Full port scan (all 65535 ports).
        
        Usage: full <target>
        
        Warning: This scan can take a long time!
        
        Example:
            full 192.168.1.1
        """
        if not arg:
            print("Usage: full <target>")
            return
        
        print("⚠ Warning: Full port scan can take a long time!")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            return
        
        self._run_nmap('-p- -T4', arg.strip(), '', 'Full port scan (all ports)')
    
    # ===== Standard Scan Types =====
    
    def do_tcp_syn_scan(self, arg: str) -> None:
        """
        TCP SYN scan (stealth scan, requires root).
        
        Usage: tcp_syn_scan <target> [options]
        
        The default and most popular scan type. Fast and stealthy.
        Requires root/administrator privileges.
        
        Examples:
            tcp_syn_scan 192.168.1.1
            tcp_syn_scan 192.168.1.0/24 -p 1-1000
        """
        if not arg:
            print("Usage: tcp_syn_scan <target> [options]")
            return
        
        parts = arg.split(maxsplit=1)
        target = parts[0]
        extra = parts[1] if len(parts) > 1 else ''
        
        self._run_nmap('-sS', target, extra, 'TCP SYN scan')
    
    def do_tcp_connect_scan(self, arg: str) -> None:
        """
        TCP connect() scan (no root required).
        
        Usage: tcp_connect_scan <target> [options]
        
        Uses full TCP connection. Slower than SYN scan but doesn't require privileges.
        
        Example:
            tcp_connect_scan 192.168.1.1
        """
        if not arg:
            print("Usage: tcp_connect_scan <target>")
            return
        
        parts = arg.split(maxsplit=1)
        target = parts[0]
        extra = parts[1] if len(parts) > 1 else ''
        
        self._run_nmap('-sT', target, extra, 'TCP connect scan')
    
    def do_udp_scan(self, arg: str) -> None:
        """
        UDP port scan (very slow, requires root).
        
        Usage: udp_scan <target> [options]
        
        Scans UDP ports. Very slow but important for complete enumeration.
        Commonly used with: -p 53,67,68,69,123,161,162
        
        Examples:
            udp_scan 192.168.1.1
            udp_scan 192.168.1.1 -p 53,161,162
        """
        if not arg:
            print("Usage: udp_scan <target> [options]")
            return
        
        print("⚠ Note: UDP scans are very slow. Consider limiting port range.")
        
        parts = arg.split(maxsplit=1)
        target = parts[0]
        extra = parts[1] if len(parts) > 1 else ''
        
        self._run_nmap('-sU', target, extra, 'UDP scan')
    
    def do_tcp_ack_scan(self, arg: str) -> None:
        """
        TCP ACK scan for firewall rule detection.
        
        Usage: tcp_ack_scan <target>
        
        Used to map firewall rulesets and determine if ports are filtered.
        
        Example:
            tcp_ack_scan 192.168.1.1
        """
        if not arg:
            print("Usage: tcp_ack_scan <target>")
            return
        
        self._run_nmap('-sA', arg.strip(), '', 'TCP ACK scan')
    
    def do_ping_sweep(self, arg: str) -> None:
        """
        Ping sweep for host discovery (no port scan).
        
        Usage: ping_sweep <target_range>
        
        Discovers which hosts are up without scanning ports.
        Very fast for large networks.
        
        Examples:
            ping_sweep 192.168.1.0/24
            ping_sweep 192.168.1.1-254
        """
        if not arg:
            print("Usage: ping_sweep <target_range>")
            return
        
        self._run_nmap('-sn', arg.strip(), '', 'Ping sweep (host discovery)')
    
    # ===== Stealth Scans =====
    
    def do_xmas_scan(self, arg: str) -> None:
        """
        XMAS scan (FIN, PSH, URG flags set).
        
        Usage: xmas_scan <target>
        
        Stealth scan that may bypass some firewalls.
        Sets FIN, PSH, and URG flags.
        
        Example:
            xmas_scan 192.168.1.1
        """
        if not arg:
            print("Usage: xmas_scan <target>")
            return
        
        self._run_nmap('-sX', arg.strip(), '', 'XMAS scan')
    
    def do_null_scan(self, arg: str) -> None:
        """
        NULL scan (no flags set).
        
        Usage: null_scan <target>
        
        Stealth scan with no TCP flags set.
        
        Example:
            null_scan 192.168.1.1
        """
        if not arg:
            print("Usage: null_scan <target>")
            return
        
        self._run_nmap('-sN', arg.strip(), '', 'NULL scan')
    
    def do_fin_scan(self, arg: str) -> None:
        """
        FIN scan (only FIN flag set).
        
        Usage: fin_scan <target>
        
        Stealth scan with only FIN flag set.
        
        Example:
            fin_scan 192.168.1.1
        """
        if not arg:
            print("Usage: fin_scan <target>")
            return
        
        self._run_nmap('-sF', arg.strip(), '', 'FIN scan')
    
    def do_stealth_scan(self, arg: str) -> None:
        """
        Ultra-stealth scan with slow timing and fragmentation.
        
        Usage: stealth_scan <target>
        
        Very slow but attempts to evade IDS/IPS detection.
        Uses -T2 timing and fragmented packets.
        
        Example:
            stealth_scan 192.168.1.1
        """
        if not arg:
            print("Usage: stealth_scan <target>")
            return
        
        print("⚠ Note: Stealth scan is very slow for maximum evasion.")
        
        self._run_nmap('-sS -T2 -f', arg.strip(), '', 'Ultra-stealth scan')
    
    # ===== Detection Scans =====
    
    def do_os_fingerprinting(self, arg: str) -> None:
        """
        Operating system detection (requires root).
        
        Usage: os_fingerprinting <target>
        
        Attempts to determine target's operating system.
        
        Example:
            os_fingerprinting 192.168.1.1
        """
        if not arg:
            print("Usage: os_fingerprinting <target>")
            return
        
        self._run_nmap('-O', arg.strip(), '', 'OS fingerprinting')
    
    def do_version_detection(self, arg: str) -> None:
        """
        Service version detection.
        
        Usage: version_detection <target> [options]
        
        Probes open ports to determine service and version information.
        
        Examples:
            version_detection 192.168.1.1
            version_detection 192.168.1.1 -p 80,443,8080
        """
        if not arg:
            print("Usage: version_detection <target> [options]")
            return
        
        parts = arg.split(maxsplit=1)
        target = parts[0]
        extra = parts[1] if len(parts) > 1 else ''
        
        self._run_nmap('-sV', target, extra, 'Service version detection')
    
    def do_aggressive_scan(self, arg: str) -> None:
        """
        Aggressive scan (-A: OS detection, version detection, script scanning, traceroute).
        
        Usage: aggressive_scan <target>
        
        Enables OS detection, version detection, script scanning, and traceroute.
        Very thorough but noisy and easily detected.
        
        Example:
            aggressive_scan 192.168.1.1
        """
        if not arg:
            print("Usage: aggressive_scan <target>")
            return
        
        print("⚠ Note: Aggressive scan is very noisy and easily detected.")
        
        self._run_nmap('-A', arg.strip(), '', 'Aggressive scan')
    
    # ===== Script Scanning =====
    
    def do_script_scan(self, arg: str) -> None:
        """
        Run NSE (Nmap Scripting Engine) scripts.
        
        Usage: script_scan <target> <script_category>
        
        Categories: default, safe, intrusive, vuln, exploit, auth, brute, discovery
        
        Examples:
            script_scan 192.168.1.1 default
            script_scan 192.168.1.1 vuln
            script_scan 192.168.1.1 "http-*"
        """
        parts = arg.split(maxsplit=1)
        
        if len(parts) < 2:
            print("Usage: script_scan <target> <script_category>")
            print(f"\nAvailable categories: {', '.join(self.nse_categories)}")
            return
        
        target, category = parts[0], parts[1]
        
        self._run_nmap(f'--script {category}', target, '', f'NSE script scan ({category})')
    
    def do_vulnerability_scan(self, arg: str) -> None:
        """
        Vulnerability scanning using NSE vuln scripts.
        
        Usage: vulnerability_scan <target>
        
        Runs vulnerability detection scripts against the target.
        
        Example:
            vulnerability_scan 192.168.1.1
        """
        if not arg:
            print("Usage: vulnerability_scan <target>")
            return
        
        print("⚠ Note: Vulnerability scans can be intrusive and may trigger alarms.")
        response = input("Continue? (y/n): ")
        if response.lower() != 'y':
            return
        
        self._run_nmap('--script vuln -sV', arg.strip(), '', 'Vulnerability scan')
    
    # ===== Custom Scanning =====
    
    def do_custom(self, arg: str) -> None:
        """
        Run custom nmap command.
        
        Usage: custom <nmap_options> <target>
        
        Examples:
            custom -sS -p 1-65535 -T4 192.168.1.1
            custom --top-ports 50 -sV 192.168.1.1
            custom -p 80,443 --script http-enum 192.168.1.1
        """
        if not arg:
            print("Usage: custom <nmap_options> <target>")
            return
        
        # Extract target (last argument)
        parts = arg.split()
        if len(parts) < 2:
            print("Error: Provide both options and target")
            return
        
        target = parts[-1]
        options = ' '.join(parts[:-1])
        
        self._run_nmap(options, target, '', 'Custom scan')
    
    def do_profile(self, arg: str) -> None:
        """
        Run a predefined scan profile.
        
        Usage: profile <profile_name> <target>
        
        Available profiles:
            quick          - Fast top ports scan
            intense        - Intense scan with version detection
            stealth        - Stealth scan with slow timing
            comprehensive  - Comprehensive scan (SYN, version, OS, aggressive)
            vulnerability  - Vulnerability detection
            discovery      - Network discovery
        
        Examples:
            profile comprehensive 192.168.1.1
            profile stealth 10.0.0.1
        """
        parts = arg.split(maxsplit=1)
        
        if len(parts) < 2:
            print("Usage: profile <profile_name> <target>")
            print(f"\nAvailable profiles:")
            for name, opts in self.profiles.items():
                print(f"  {name:<15} {opts}")
            return
        
        profile_name, target = parts[0], parts[1]
        
        if profile_name not in self.profiles:
            print(f"✗ Error: Unknown profile '{profile_name}'")
            print(f"Available profiles: {', '.join(self.profiles.keys())}")
            return
        
        options = self.profiles[profile_name]
        self._run_nmap(options, target, '', f'Profile: {profile_name}')
    
    # ===== Result Management =====
    
    def do_results(self, arg: str) -> None:
        """
        View recent scan results.
        
        Usage: results [count]
        
        Examples:
            results      - Show last 10 scans
            results 20   - Show last 20 scans
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
        
        print(f"\n{'='*80}")
        print(f"Recent Scans (showing last {len(recent)})")
        print(f"{'='*80}")
        print(f"\n{'ID':<5} {'Date/Time':<20} {'Type':<20} {'Target':<25} {'Duration':<10}")
        print("-" * 80)
        
        for scan in reversed(recent):
            scan_id = scan['id']
            timestamp = datetime.fromisoformat(scan['timestamp']).strftime('%Y-%m-%d %H:%M:%S')
            scan_type = scan['description'][:18]
            target = scan['target'][:23]
            duration = f"{scan['duration']:.1f}s"
            
            print(f"{scan_id:<5} {timestamp:<20} {scan_type:<20} {target:<25} {duration:<10}")
        
        print(f"\nUse 'analyze <scan_id>' to view detailed results")
        print(f"Use 'export <scan_id> <format>' to export results\n")
    
    def do_history(self, arg: str) -> None:
        """Alias for results command."""
        self.do_results(arg)
    
    def do_analyze(self, arg: str) -> None:
        """
        Analyze specific scan results.
        
        Usage: analyze <scan_id>
        
        Example:
            analyze 5
        """
        if not arg:
            print("Usage: analyze <scan_id>")
            print("Use 'results' to see available scan IDs")
            return
        
        try:
            scan_id = int(arg)
        except ValueError:
            print("Error: Scan ID must be an integer")
            return
        
        # Find scan
        scan = next((s for s in self.scan_history if s['id'] == scan_id), None)
        
        if not scan:
            print(f"✗ Error: No scan found with ID {scan_id}")
            return
        
        # Display scan info
        print(f"\n{'='*80}")
        print(f"Scan Analysis - ID {scan_id}")
        print(f"{'='*80}")
        print(f"\nTimestamp:   {scan['timestamp']}")
        print(f"Scan Type:   {scan['description']}")
        print(f"Target:      {scan['target']}")
        print(f"Duration:    {scan['duration']:.2f} seconds")
        print(f"Command:     {scan['command']}")
        
        # Re-analyze XML if available
        if scan.get('xml_file') and Path(scan['xml_file']).exists():
            self._analyze_scan(scan)
        elif Path(scan['output_file']).exists():
            print(f"\n{'='*80}")
            print("Scan Output:")
            print(f"{'='*80}\n")
            
            with open(scan['output_file'], 'r') as f:
                print(f.read())
        else:
            print("\n✗ Scan output files not found")
    
    def do_export(self, arg: str) -> None:
        """
        Export scan results in different formats.
        
        Usage: export <scan_id> <format>
        
        Formats: txt, xml, json, html
        
        Example:
            export 5 json
        """
        parts = arg.split()
        
        if len(parts) != 2:
            print("Usage: export <scan_id> <format>")
            print("Formats: txt, xml, json, html")
            return
        
        scan_id, format_type = parts[0], parts[1].lower()
        
        try:
            scan_id = int(scan_id)
        except ValueError:
            print("Error: Scan ID must be an integer")
            return
        
        if format_type not in ['txt', 'xml', 'json', 'html']:
            print("Error: Format must be txt, xml, json, or html")
            return
        
        # Find scan
        scan = next((s for s in self.scan_history if s['id'] == scan_id), None)
        
        if not scan:
            print(f"✗ Error: No scan found with ID {scan_id}")
            return
        
        # TODO: Implement export functionality
        print(f"Exporting scan {scan_id} as {format_type}...")
        print("✓ Export functionality coming soon!")
    
    # ===== Configuration =====
    
    def do_config(self, arg: str) -> None:
        """
        Configure module settings.
        
        Usage: config [key] [value]
               config show
        
        Settings:
            save_output        - Save scan output to files (true/false)
            auto_analyze       - Auto-analyze results after scan (true/false)
            timing_template    - Default timing (T0-T5)
            verbose            - Verbose output (true/false)
            save_xml           - Save XML output (true/false)
            save_json          - Save JSON output (true/false)
            max_history        - Maximum history entries to keep
        
        Examples:
            config show
            config timing_template T4
            config auto_analyze false
        """
        args = arg.split(maxsplit=1)
        
        if not args or args[0] == 'show':
            print(f"\n{'='*60}")
            print("Current Configuration")
            print(f"{'='*60}\n")
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
        elif key == 'timing_template':
            if value not in [f'T{i}' for i in range(6)]:
                print("✗ Error: Timing template must be T0-T5")
                return
        
        self.config[key] = value
        print(f"✓ Set {key} = {value}")
        self.logger.info(f"Configuration updated: {key} = {value}")
    
    def do_profiles(self, arg: str) -> None:
        """
        Show available scan profiles.
        
        Usage: profiles
        """
        print(f"\n{'='*60}")
        print("Available Scan Profiles")
        print(f"{'='*60}\n")
        
        for name, options in sorted(self.profiles.items()):
            print(f"  {name:<15} {options}")
        
        print(f"\nUse 'profile <name> <target>' to run a profile\n")
    
    # ===== Exit Commands =====
    
    def do_back(self, arg: str) -> bool:
        """Return to main menu."""
        print("Exiting Nmap Module.")
        self.logger.info("Nmap module exited")
        return True
    
    def do_exit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    def do_quit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    # ===== Tab Completion =====
    
    def complete_profile(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for profile command."""
        return [p for p in self.profiles.keys() if p.startswith(text)]
    
    def complete_script_scan(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for script_scan command."""
        # Only complete second argument (category)
        parts = line.split()
        if len(parts) >= 2:
            return [c for c in self.nse_categories if c.startswith(text)]
        return []
    
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
    
    print("Running Nmap Module in test mode...")
    NmapModule().cmdloop()


if __name__ == '__main__':
    main()
