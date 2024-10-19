import cmd
import subprocess


class VulnerabilityScanningModule(cmd.Cmd):
    """
        A command line interface (CLI) for vulnerability scanning using Nikto.

        Attributes:
            prompt (str): Command prompt string.
            intro (str): Introduction message displayed when the module starts.

        Methods:
            do_scan(arg):
                Scan a web server with Nikto: scan <URL>.
                If no URL is specified, it prompts the user to provide one.

            do_quit(arg):
                Quit the Vulnerability Scanning Module.
                Prints an exiting message and returns True to stop the command loop.

            run_nikto_scan(url):
                Run Nikto scan against a specified URL.
                Constructs and runs the command using subprocess.
    """
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
