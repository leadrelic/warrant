import cmd
import subprocess


class NmapModule(cmd.Cmd):
    prompt = '(nmap) '
    intro = 'Nmap module. Type help or ? to list commands.\n'

    def do_quit(self, arg):
        """Return to the main menu."""
        print("Exiting Nmap Module.")
        return True

    def do_tcp_syn_scan(self, ip):
        """Perform a TCP SYN port scan.\nUsage: tcp_syn_scan <target_ip>"""
        self.run_nmap('-sS', ip)

    def do_tcp_connect_scan(self, ip):
        """Perform a TCP connect() scan.\nUsage: tcp_connect_scan <target_ip>"""
        self.run_nmap('-sT', ip)

    def do_udp_scan(self, ip):
        """Perform a UDP scan.\nUsage: udp_scan <target_ip>"""
        self.run_nmap('-sU', ip)

    def do_tcp_ack_scan(self, ip):
        """Perform a TCP ACK scan.\nUsage: tcp_ack_scan <target_ip>"""
        self.run_nmap('-sA', ip)

    def do_ping_sweep(self, ip):
        """Perform a ping sweep.\nUsage: ping_sweep <target_ip_range>"""
        self.run_nmap('-sn', ip)

    def do_xmas_scan(self, ip):
        """Perform an XMAS scan.\nUsage: xmas_scan <target_ip>"""
        self.run_nmap('-sX', ip)

    def do_null_scan(self, ip):
        """Perform a NULL scan.\nUsage: null_scan <target_ip>"""
        self.run_nmap('-sN', ip)

    def do_fin_scan(self, ip):
        """Perform a FIN scan.\nUsage: fin_scan <target_ip>"""
        self.run_nmap('-sF', ip)

    def do_os_fingerprinting(self, ip):
        """Perform OS fingerprinting.\nUsage: os_fingerprinting <target_ip>"""
        self.run_nmap('-O', ip)

    def do_version_detection(self, ip):
        """Perform version detection.\nUsage: version_detection <target_ip>"""
        self.run_nmap('-sV', ip)

    def run_nmap(self, scan_type, ip):
        """Helper function to run nmap scans."""
        if ip:
            cmd = f'nmap {scan_type} {ip}'
            print(f"Running command: {cmd}")
            try:
                subprocess.run(cmd.split())
            except Exception as e:
                print(f'Error running command: {cmd}\n{e}')
        else:
            print("IP address or range is required.")