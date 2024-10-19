import cmd
import subprocess


class VulnerabilityScanningModule(cmd.Cmd):
    prompt = '(vulnscan) '
    intro = 'Vulnerability Scanning module with Nikto. Type help or ? to list commands.\n'

    def do_scan(self, arg):
        "Scan a web server with Nikto: scan <URL>"
        if not arg:
            print("You must specify a URL to scan.")
            return
        self.run_nikto_scan(arg)

    def do_quit(self, arg):
        "Quit the Vulnerability Scanning Module."
        print("Exiting Vulnerability Scanning Module.")
        return True

    def run_nikto_scan(self, url):
        "Run Nikto scan against a specified URL."
        cmd = f'nikto -h {url}'
        print(f"Running command: {cmd}")
        try:
            subprocess.run(cmd, shell=True)
        except Exception as e:
            print(f'Error running Nikto: {e}')
