"""
IP Trace Module
Advanced IP address geolocation and information gathering.
"""

import cmd
import requests
import logging
import json
import socket
import subprocess
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime
import time


class IPTraceModule(cmd.Cmd):
    """
    Advanced IP trace module with multiple lookup services and comprehensive analysis.
    
    Features:
    - Multiple IP lookup services (ip-api, ipinfo, ipwhois)
    - Geolocation with coordinates
    - ISP and organization information
    - Reverse DNS lookup
    - Network route tracing (traceroute)
    - Ping latency testing
    - IP reputation checking
    - WHOIS information
    - Batch IP lookup
    - Export results to JSON/CSV
    - Lookup history
    """
    
    prompt = '(iptrace) '
    intro = '''
╔══════════════════════════════════════════════════════════════╗
║                 IP Trace & Geolocation Module                 ║
╚══════════════════════════════════════════════════════════════╝

Quick Commands:
  trace <ip>              - Quick IP lookup with all available info
  geolocate <ip>          - Get geolocation information
  lookup <ip>             - Detailed IP information
  
Advanced Features:
  whois <ip>              - WHOIS information lookup
  traceroute <ip>         - Trace network route to IP
  ping <ip>               - Test connectivity and latency
  reverse_dns <ip>        - Reverse DNS lookup
  reputation <ip>         - Check IP reputation
  
Batch Operations:
  batch_trace <file>      - Trace multiple IPs from file
  compare <ip1> <ip2>     - Compare two IP addresses
  
Utilities:
  history                 - View lookup history
  export <filename>       - Export last result to file
  config                  - Configure module settings
  services                - Show available lookup services

Type 'help <command>' for detailed usage.
Type 'back' or 'exit' to return to main menu.
'''
    
    def __init__(self):
        """Initialize the IP trace module."""
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configuration
        self.config = {
            'primary_service': 'ip-api',
            'timeout': 10,
            'show_raw_data': False,
            'auto_traceroute': False,
            'auto_reverse_dns': True,
            'save_history': True,
            'max_history': 100
        }
        
        # Available services
        self.services = {
            'ip-api': {
                'url': 'http://ip-api.com/json/{}',
                'free': True,
                'rate_limit': '45/minute'
            },
            'ipinfo': {
                'url': 'https://ipinfo.io/{}',
                'free': True,
                'rate_limit': '50k/month'
            },
            'ipwhois': {
                'url': 'http://ipwho.is/{}',
                'free': True,
                'rate_limit': '10k/month'
            }
        }
        
        # Lookup history
        self.history = []
        self.last_result = None
        
        # Results directory
        self.results_dir = Path.home() / '.pentest_toolkit' / 'ip_traces'
        self.results_dir.mkdir(parents=True, exist_ok=True)
        
        self._load_history()
    
    # ===== Quick Commands =====
    
    def do_trace(self, arg: str) -> None:
        """
        Quick comprehensive IP trace.
        
        Usage: trace <ip_address>
        
        Provides all available information about an IP address including:
        - Geolocation (country, city, coordinates)
        - ISP and organization
        - Reverse DNS
        - Network information
        
        Examples:
            trace 8.8.8.8
            trace 1.1.1.1
            trace 192.168.1.1
        """
        if not arg:
            print("✗ Error: Please specify an IP address")
            print("Usage: trace <ip_address>")
            return
        
        ip = arg.strip()
        
        if not self._validate_ip(ip):
            return
        
        print(f"\n{'='*70}")
        print(f"IP Trace: {ip}")
        print(f"{'='*70}\n")
        
        # Gather information
        info = self._comprehensive_lookup(ip)
        
        if info:
            self._display_comprehensive_info(info)
            self.last_result = info
            
            # Save to history
            if self.config['save_history']:
                self._add_to_history(ip, info)
        else:
            print("✗ Failed to retrieve IP information")
    
    def do_lookup(self, arg: str) -> None:
        """
        Detailed IP information lookup.
        
        Usage: lookup <ip_address> [service]
        
        Services: ip-api (default), ipinfo, ipwhois
        
        Examples:
            lookup 8.8.8.8
            lookup 1.1.1.1 ipinfo
        """
        parts = arg.split()
        
        if not parts:
            print("Usage: lookup <ip_address> [service]")
            return
        
        ip = parts[0]
        service = parts[1] if len(parts) > 1 else self.config['primary_service']
        
        if not self._validate_ip(ip):
            return
        
        if service not in self.services:
            print(f"✗ Error: Unknown service '{service}'")
            print(f"Available: {', '.join(self.services.keys())}")
            return
        
        print(f"\nQuerying {service} for {ip}...")
        
        data = self._query_service(ip, service)
        
        if data:
            print(f"\n{'='*70}")
            print(f"IP Information ({service})")
            print(f"{'='*70}\n")
            
            self._display_service_data(data, service)
            
            if self.config['show_raw_data']:
                print(f"\n{'='*70}")
                print("Raw JSON Data:")
                print(f"{'='*70}")
                print(json.dumps(data, indent=2))
        else:
            print(f"✗ Failed to retrieve data from {service}")
    
    def do_geolocate(self, arg: str) -> None:
        """
        Get geolocation information for an IP.
        
        Usage: geolocate <ip_address>
        
        Returns: Country, region, city, coordinates, timezone
        
        Example:
            geolocate 8.8.8.8
        """
        if not arg:
            print("Usage: geolocate <ip_address>")
            return
        
        ip = arg.strip()
        
        if not self._validate_ip(ip):
            return
        
        data = self._query_service(ip, 'ip-api')
        
        if data:
            print(f"\n{'='*70}")
            print(f"Geolocation: {ip}")
            print(f"{'='*70}\n")
            
            print(f"Country:     {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
            print(f"Region:      {data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})")
            print(f"City:        {data.get('city', 'N/A')}")
            print(f"ZIP Code:    {data.get('zip', 'N/A')}")
            print(f"Timezone:    {data.get('timezone', 'N/A')}")
            print(f"Coordinates: {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
            
            if data.get('lat') and data.get('lon'):
                maps_url = f"https://www.google.com/maps?q={data['lat']},{data['lon']}"
                print(f"Maps:        {maps_url}")
            
            print(f"\n{'='*70}\n")
        else:
            print("✗ Failed to retrieve geolocation data")
    
    # ===== Advanced Lookups =====
    
    def do_whois(self, arg: str) -> None:
        """
        Perform WHOIS lookup on IP address.
        
        Usage: whois <ip_address>
        
        Requires 'whois' command to be installed.
        
        Example:
            whois 8.8.8.8
        """
        if not arg:
            print("Usage: whois <ip_address>")
            return
        
        ip = arg.strip()
        
        if not self._validate_ip(ip):
            return
        
        try:
            print(f"\n{'='*70}")
            print(f"WHOIS Information: {ip}")
            print(f"{'='*70}\n")
            
            result = subprocess.run(
                ['whois', ip],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                print(result.stdout)
            else:
                print(f"✗ WHOIS lookup failed")
                print(f"Error: {result.stderr}")
            
        except FileNotFoundError:
            print("✗ Error: 'whois' command not found")
            print("  Install with: sudo apt-get install whois")
        except subprocess.TimeoutExpired:
            print("✗ Error: WHOIS lookup timed out")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def do_traceroute(self, arg: str) -> None:
        """
        Trace the network route to an IP address.
        
        Usage: traceroute <ip_address>
        
        Shows the path packets take to reach the destination.
        
        Example:
            traceroute 8.8.8.8
        """
        if not arg:
            print("Usage: traceroute <ip_address>")
            return
        
        ip = arg.strip()
        
        if not self._validate_ip(ip):
            return
        
        try:
            print(f"\n{'='*70}")
            print(f"Traceroute to {ip}")
            print(f"{'='*70}\n")
            
            # Use traceroute on Linux/Mac, tracert on Windows
            cmd = ['traceroute', ip]
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.returncode == 0:
                    print(result.stdout)
                else:
                    # Try Windows command
                    result = subprocess.run(
                        ['tracert', ip],
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    print(result.stdout)
                    
            except FileNotFoundError:
                print("✗ Error: traceroute command not found")
                print("  Install with: sudo apt-get install traceroute")
            
        except subprocess.TimeoutExpired:
            print("✗ Error: Traceroute timed out")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def do_ping(self, arg: str) -> None:
        """
        Ping an IP address to test connectivity and latency.
        
        Usage: ping <ip_address> [count]
        
        Default count: 4 packets
        
        Examples:
            ping 8.8.8.8
            ping 1.1.1.1 10
        """
        parts = arg.split()
        
        if not parts:
            print("Usage: ping <ip_address> [count]")
            return
        
        ip = parts[0]
        count = int(parts[1]) if len(parts) > 1 else 4
        
        if not self._validate_ip(ip):
            return
        
        try:
            print(f"\n{'='*70}")
            print(f"Pinging {ip} ({count} packets)")
            print(f"{'='*70}\n")
            
            # Use ping command
            import platform
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            
            result = subprocess.run(
                ['ping', param, str(count), ip],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            print(result.stdout)
            
        except subprocess.TimeoutExpired:
            print("✗ Error: Ping timed out")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def do_reverse_dns(self, arg: str) -> None:
        """
        Perform reverse DNS lookup.
        
        Usage: reverse_dns <ip_address>
        
        Attempts to resolve IP to hostname.
        
        Example:
            reverse_dns 8.8.8.8
        """
        if not arg:
            print("Usage: reverse_dns <ip_address>")
            return
        
        ip = arg.strip()
        
        if not self._validate_ip(ip):
            return
        
        try:
            print(f"\nReverse DNS lookup for {ip}...")
            hostname = socket.gethostbyaddr(ip)[0]
            
            print(f"\n{'='*70}")
            print(f"Reverse DNS Result")
            print(f"{'='*70}")
            print(f"\nIP:        {ip}")
            print(f"Hostname:  {hostname}")
            print(f"{'='*70}\n")
            
        except socket.herror:
            print(f"\n✗ No reverse DNS entry found for {ip}\n")
        except Exception as e:
            print(f"\n✗ Error: {e}\n")
    
    def do_reputation(self, arg: str) -> None:
        """
        Check IP reputation (basic check).
        
        Usage: reputation <ip_address>
        
        Checks if IP is associated with known threats.
        
        Example:
            reputation 8.8.8.8
        """
        if not arg:
            print("Usage: reputation <ip_address>")
            return
        
        ip = arg.strip()
        
        if not self._validate_ip(ip):
            return
        
        print(f"\n{'='*70}")
        print(f"IP Reputation Check: {ip}")
        print(f"{'='*70}\n")
        
        # Get comprehensive data
        data = self._query_service(ip, 'ipwhois')
        
        if data:
            # Check for VPN/Proxy indicators
            is_proxy = data.get('is_proxy', False)
            
            print(f"Type:        {'Proxy/VPN' if is_proxy else 'Regular'}")
            print(f"Connection:  {data.get('connection', {}).get('isp', 'N/A')}")
            
            # Additional checks would go here
            print(f"\n✓ Basic reputation check complete")
            print(f"  For comprehensive checks, use dedicated threat intelligence services")
        else:
            print("✗ Unable to retrieve reputation data")
        
        print(f"\n{'='*70}\n")
    
    # ===== Batch Operations =====
    
    def do_batch_trace(self, arg: str) -> None:
        """
        Trace multiple IP addresses from a file.
        
        Usage: batch_trace <filename>
        
        File format: One IP address per line
        
        Example:
            batch_trace ip_list.txt
        """
        if not arg:
            print("Usage: batch_trace <filename>")
            return
        
        filename = arg.strip()
        
        try:
            with open(filename, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            print(f"\n{'='*70}")
            print(f"Batch IP Trace: {len(ips)} addresses")
            print(f"{'='*70}\n")
            
            results = []
            
            for i, ip in enumerate(ips, 1):
                print(f"[{i}/{len(ips)}] Tracing {ip}...")
                
                info = self._comprehensive_lookup(ip)
                if info:
                    results.append(info)
                    print(f"  ✓ {info.get('country', 'Unknown')} - {info.get('city', 'Unknown')}")
                else:
                    print(f"  ✗ Failed")
                
                # Rate limiting
                if i < len(ips):
                    time.sleep(1.5)  # Respect API rate limits
            
            # Save results
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.results_dir / f'batch_trace_{timestamp}.json'
            
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\n{'='*70}")
            print(f"Batch Trace Complete")
            print(f"{'='*70}")
            print(f"\nTotal:       {len(ips)}")
            print(f"Successful:  {len(results)}")
            print(f"Failed:      {len(ips) - len(results)}")
            print(f"Results:     {output_file}")
            print(f"{'='*70}\n")
            
        except FileNotFoundError:
            print(f"✗ Error: File '{filename}' not found")
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def do_compare(self, arg: str) -> None:
        """
        Compare two IP addresses.
        
        Usage: compare <ip1> <ip2>
        
        Example:
            compare 8.8.8.8 1.1.1.1
        """
        parts = arg.split()
        
        if len(parts) != 2:
            print("Usage: compare <ip1> <ip2>")
            return
        
        ip1, ip2 = parts
        
        if not (self._validate_ip(ip1) and self._validate_ip(ip2)):
            return
        
        print(f"\n{'='*70}")
        print(f"IP Comparison")
        print(f"{'='*70}\n")
        
        info1 = self._comprehensive_lookup(ip1)
        info2 = self._comprehensive_lookup(ip2)
        
        if info1 and info2:
            print(f"{'Attribute':<20} {'IP 1 (' + ip1 + ')':<30} {'IP 2 (' + ip2 + ')':<30}")
            print("-" * 80)
            
            attributes = ['country', 'city', 'isp', 'org', 'timezone']
            
            for attr in attributes:
                val1 = info1.get(attr, 'N/A')
                val2 = info2.get(attr, 'N/A')
                match = "✓" if val1 == val2 else "✗"
                print(f"{attr.capitalize():<20} {str(val1):<30} {str(val2):<30} {match}")
            
            print(f"\n{'='*70}\n")
        else:
            print("✗ Failed to retrieve comparison data")
    
    # ===== History and Export =====
    
    def do_history(self, arg: str) -> None:
        """
        View IP lookup history.
        
        Usage: history [count]
        
        Example:
            history     - Show last 10 lookups
            history 20  - Show last 20 lookups
        """
        count = 10
        if arg:
            try:
                count = int(arg)
            except ValueError:
                print("Error: Count must be an integer")
                return
        
        if not self.history:
            print("No lookup history available")
            return
        
        recent = self.history[-count:]
        
        print(f"\n{'='*70}")
        print(f"Lookup History (last {len(recent)})")
        print(f"{'='*70}")
        print(f"\n{'IP Address':<20} {'Country':<20} {'City':<20} {'Timestamp':<20}")
        print("-" * 80)
        
        for record in reversed(recent):
            ip = record.get('ip', 'N/A')
            country = record.get('country', 'N/A')
            city = record.get('city', 'N/A')
            timestamp = record.get('timestamp', 'N/A')[:19]  # Trim microseconds
            
            print(f"{ip:<20} {country:<20} {city:<20} {timestamp:<20}")
        
        print(f"\n{'='*70}\n")
    
    def do_export(self, arg: str) -> None:
        """
        Export last lookup result to file.
        
        Usage: export <filename>
        
        Supports JSON and CSV formats.
        
        Examples:
            export result.json
            export data.csv
        """
        if not arg:
            print("Usage: export <filename>")
            return
        
        if not self.last_result:
            print("✗ Error: No lookup result to export")
            print("  Perform a lookup first using 'trace' or 'lookup'")
            return
        
        filename = arg.strip()
        filepath = self.results_dir / filename
        
        try:
            if filename.endswith('.json'):
                with open(filepath, 'w') as f:
                    json.dump(self.last_result, f, indent=2)
            elif filename.endswith('.csv'):
                import csv
                with open(filepath, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Key', 'Value'])
                    for key, value in self.last_result.items():
                        writer.writerow([key, value])
            else:
                print("✗ Error: Unsupported format")
                print("  Supported: .json, .csv")
                return
            
            print(f"✓ Result exported to: {filepath}")
            
        except Exception as e:
            print(f"✗ Export error: {e}")
    
    # ===== Configuration =====
    
    def do_services(self, arg: str) -> None:
        """
        Show available IP lookup services.
        
        Usage: services
        """
        print(f"\n{'='*70}")
        print("Available Lookup Services")
        print(f"{'='*70}\n")
        
        for name, info in self.services.items():
            print(f"• {name}")
            print(f"  URL:        {info['url']}")
            print(f"  Free:       {'Yes' if info['free'] else 'No'}")
            print(f"  Rate Limit: {info['rate_limit']}")
            print()
        
        print(f"{'='*70}\n")
    
    def do_config(self, arg: str) -> None:
        """
        Configure module settings.
        
        Usage: config [key] [value]
               config show
        
        Examples:
            config show
            config primary_service ipinfo
            config auto_traceroute true
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
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            print(f"✗ Error: Invalid IP address '{ip}'")
            return False
    
    def _query_service(self, ip: str, service: str) -> Optional[Dict]:
        """Query a specific IP lookup service."""
        if service not in self.services:
            return None
        
        url = self.services[service]['url'].format(ip)
        
        try:
            response = requests.get(url, timeout=self.config['timeout'])
            
            if response.status_code == 200:
                return response.json()
            else:
                self.logger.error(f"Service {service} returned {response.status_code}")
                return None
                
        except requests.Timeout:
            self.logger.error(f"Timeout querying {service}")
            return None
        except Exception as e:
            self.logger.error(f"Error querying {service}: {e}")
            return None
    
    def _comprehensive_lookup(self, ip: str) -> Optional[Dict]:
        """Perform comprehensive IP lookup using primary service."""
        data = self._query_service(ip, self.config['primary_service'])
        
        if not data:
            # Try fallback services
            for service in self.services.keys():
                if service != self.config['primary_service']:
                    data = self._query_service(ip, service)
                    if data:
                        break
        
        # Add reverse DNS if configured
        if data and self.config['auto_reverse_dns']:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                data['hostname'] = hostname
            except:
                data['hostname'] = 'N/A'
        
        return data
    
    def _display_comprehensive_info(self, info: Dict) -> None:
        """Display comprehensive IP information."""
        print(f"IP Address:  {info.get('query', info.get('ip', 'N/A'))}")
        print(f"Hostname:    {info.get('hostname', 'N/A')}")
        print(f"\nLocation:")
        print(f"  Country:   {info.get('country', 'N/A')} ({info.get('countryCode', 'N/A')})")
        print(f"  Region:    {info.get('regionName', info.get('region', 'N/A'))}")
        print(f"  City:      {info.get('city', 'N/A')}")
        print(f"  ZIP:       {info.get('zip', 'N/A')}")
        print(f"  Timezone:  {info.get('timezone', 'N/A')}")
        
        if info.get('lat') and info.get('lon'):
            print(f"  Coords:    {info['lat']}, {info['lon']}")
        
        print(f"\nNetwork:")
        print(f"  ISP:       {info.get('isp', 'N/A')}")
        print(f"  Org:       {info.get('org', info.get('as', 'N/A'))}")
        print(f"  AS:        {info.get('as', 'N/A')}")
        
        print(f"\n{'='*70}\n")
    
    def _display_service_data(self, data: Dict, service: str) -> None:
        """Display service-specific data."""
        # Display all key-value pairs
        for key, value in data.items():
            if isinstance(value, dict):
                print(f"{key}:")
                for k, v in value.items():
                    print(f"  {k}: {v}")
            else:
                print(f"{key}: {value}")
    
    def _add_to_history(self, ip: str, info: Dict) -> None:
        """Add lookup to history."""
        record = {
            'timestamp': datetime.now().isoformat(),
            'ip': ip,
            'country': info.get('country', 'N/A'),
            'city': info.get('city', 'N/A'),
            'isp': info.get('isp', 'N/A')
        }
        
        self.history.append(record)
        
        # Limit history size
        if len(self.history) > self.config['max_history']:
            self.history = self.history[-self.config['max_history']:]
        
        self._save_history()
    
    def _load_history(self) -> None:
        """Load lookup history from file."""
        history_file = self.results_dir / 'lookup_history.json'
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    self.history = json.load(f)
            except Exception as e:
                self.logger.error(f"Error loading history: {e}")
    
    def _save_history(self) -> None:
        """Save lookup history to file."""
        history_file = self.results_dir / 'lookup_history.json'
        try:
            with open(history_file, 'w') as f:
                json.dump(self.history, f, indent=2)
        except Exception as e:
            self.logger.error(f"Error saving history: {e}")
    
    # ===== Exit Commands =====
    
    def do_back(self, arg: str) -> bool:
        """Return to main menu."""
        print("Exiting IP Trace Module.")
        self.logger.info("IP trace module exited")
        return True
    
    def do_exit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    def do_quit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    # ===== Tab Completion =====
    
    def complete_lookup(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for lookup command."""
        return [s for s in self.services.keys() if s.startswith(text)]
    
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
    
    print("Running IP Trace Module in test mode...")
    IPTraceModule().cmdloop()


if __name__ == '__main__':
    main()
