import cmd
import hashlib
from cryptography.fernet import Fernet


class EncryptionDecryptionModule(cmd.Cmd):
    prompt = '(encryption) '
    intro = 'Encryption/Decryption Module. Type help or ? to list commands.\n'


    def do_encrypt(self, arg):
        """Encrypt a message.\nUsage: encrypt <message>"""
        if not arg:
            print("Please provide a message to encrypt.")
            return
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        cipher_text = cipher_suite.encrypt(arg.encode())
        print(f"Encrypted message: {cipher_text.decode()}")
        print(f"Key (save this to decrypt): {key.decode()}")


    def do_decrypt(self, arg):
        """Decrypt a message.\nUsage: decrypt <encrypted_message> <key>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: decrypt <encrypted_message> <key>")
            return
        encrypted_message, key = args
        cipher_suite = Fernet(key.encode())
        try:
            plain_text = cipher_suite.decrypt(encrypted_message.encode())
            print(f"Decrypted message: {plain_text.decode()}")
        except Exception as e:
            print(f"Failed to decrypt message: {e}")


    def do_hash(self, arg):
        """Generate a hash of the message.\nUsage: hash <message> <algorithm>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: hash <message> <algorithm>")
            return
        message, algorithm = args
        try:
            if algorithm.lower() in hashlib.algorithms_available:
                hash_func = getattr(hashlib, algorithm.lower())
                hash_digest = hash_func(message.encode()).hexdigest()
                print(f"Hash ({algorithm}): {hash_digest}")
            else:
                print(f"Algorithm {algorithm} is not supported.")
        except Exception as e:
            print(f"Failed to generate hash: {e}")


    def do_quit(self, arg):
        """Return to the main menu."""
        print("Exiting Encryption/Decryption Module.")
        return True
