import cmd
import signal
import sys
from Modules.nmap import NmapModule
from Modules.trace import IPTraceModule
from Modules.vuln_scan import VulnerabilityScanningModule
from Modules.pass_crack import PasswordCrackingModule
from Modules.hashing import EncryptionDecryptionModule
from Modules.dictionary import PasswordDictionaryCreator


def signal_handler(sig, frame):
    print('\nCaught interrupt signal, exiting...')
    sys.exit(0)


# Set the signal handler for SIGINT
signal.signal(signal.SIGINT, signal_handler)


class PentestTool(cmd.Cmd):
    prompt = '(pentest) '
    intro = 'Welcome to the pentesting toolkit. Type help or ? to list commands.\n'

    def do_exit(self, arg):
        """Exit the program."""
        return True

    def do_nmap(self, arg):
        """Switch to the Nmap module."""
        try:
            NmapModule().cmdloop()
        except KeyboardInterrupt:
            print('\nReturning to main menu...')

    def do_iptrace(self, arg):
        """Switch to the IP Trace module."""
        try:
            IPTraceModule().cmdloop()
        except KeyboardInterrupt:
            print('\nReturning to main menu...')
    
    def do_vulnscan(self, arg):
        """Switch to the Vulnerability Scanning module."""
        try:
            VulnerabilityScanningModule().cmdloop()
        except KeyboardInterrupt:
            print('\nReturning to main menu...')
    
    def do_password_cracking(self, arg):
        """Switch to the Password Cracking module."""
        try:
            PasswordCrackingModule().cmdloop()
        except KeyboardInterrupt:
            print('\nReturning to main menu...')

    def do_encryption_decryption(self, arg):
        """Switch to the Encryption/Decryption module."""
        try:
            EncryptionDecryptionModule().cmdloop()
        except KeyboardInterrupt:
            print('\nReturning to main menu...')

    def do_dictionary_creator(self, arg):
        """Switch to the dictionary creator module."""
        try:
            PasswordDictionaryCreator().cmdloop()
        except KeyboardInterrupt:
            print('\nReturning to main menu...')
            
    # Add other module entry points here


if __name__ == '__main__':
    try:
        PentestTool().cmdloop()
    except KeyboardInterrupt:
        print('\nExiting the pentesting toolkit. Goodbye!')

