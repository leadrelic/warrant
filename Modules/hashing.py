"""
Encryption/Decryption/Hashing Module
Advanced cryptographic operations for penetration testing.
"""

import cmd
import hashlib
import logging
import base64
import secrets
from pathlib import Path
from typing import Optional, Dict, List
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


class EncryptionDecryptionModule(cmd.Cmd):
    """
    Advanced encryption, decryption, and hashing module.
    
    Features:
    - Multiple encryption algorithms (Fernet, AES-256, ChaCha20)
    - File encryption/decryption
    - Password-based encryption
    - Multiple hashing algorithms (MD5, SHA1, SHA256, SHA512, etc.)
    - Hash cracking with wordlists
    - Base64 encoding/decoding
    - Key generation and management
    - Rainbow table generation
    - Hash comparison and verification
    """
    
    prompt = '(crypto) '
    intro = '''
╔══════════════════════════════════════════════════════════════╗
║         Encryption/Decryption/Hashing Module                  ║
╚══════════════════════════════════════════════════════════════╝

Quick Start:
  encrypt <message>           - Encrypt a message (Fernet)
  decrypt <encrypted> <key>   - Decrypt a message
  hash <message> <algorithm>  - Generate hash
  
Encryption Commands:
  encrypt_message             - Encrypt a text message
  decrypt_message             - Decrypt a text message
  encrypt_file                - Encrypt a file
  decrypt_file                - Decrypt a file
  encrypt_password            - Password-based encryption
  decrypt_password            - Password-based decryption
  
Hashing Commands:
  hash                        - Generate hash of text
  hash_file                   - Generate hash of file
  crack_hash                  - Crack hash with wordlist
  compare_hash                - Compare hash values
  multi_hash                  - Generate multiple hash types
  
Encoding/Decoding:
  base64_encode               - Encode to Base64
  base64_decode               - Decode from Base64
  hex_encode                  - Encode to hexadecimal
  hex_decode                  - Decode from hexadecimal
  
Key Management:
  generate_key                - Generate encryption key
  derive_key                  - Derive key from password
  save_key                    - Save key to file
  load_key                    - Load key from file

Utilities:
  algorithms                  - Show available algorithms
  benchmark                   - Benchmark hash algorithms
  config                      - Configure module settings

Type 'help <command>' for detailed usage.
Type 'back' or 'exit' to return to main menu.
'''
    
    def __init__(self):
        """Initialize the crypto module."""
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configuration
        self.config = {
            'default_algorithm': 'sha256',
            'default_encryption': 'fernet',
            'key_iterations': 100000,
            'auto_save_keys': False,
            'show_key_in_output': True
        }
        
        # Key storage
        self.keys = {}
        self.key_dir = Path.home() / '.pentest_toolkit' / 'keys'
        self.key_dir.mkdir(parents=True, exist_ok=True)
        
        # Available algorithms
        self.hash_algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha224': hashlib.sha224,
            'sha256': hashlib.sha256,
            'sha384': hashlib.sha384,
            'sha512': hashlib.sha512,
            'sha3_224': hashlib.sha3_224,
            'sha3_256': hashlib.sha3_256,
            'sha3_384': hashlib.sha3_384,
            'sha3_512': hashlib.sha3_512,
            'blake2b': hashlib.blake2b,
            'blake2s': hashlib.blake2s,
        }
        
        # Hash crack history
        self.crack_attempts = []
    
    # ===== Basic Encryption/Decryption =====
    
    def do_encrypt(self, arg: str) -> None:
        """
        Quick encrypt a message using Fernet (symmetric encryption).
        
        Usage: encrypt <message>
        
        Generates a new key for each encryption. Save the key to decrypt!
        
        Example:
            encrypt Hello World!
        """
        if not arg:
            print("✗ Error: Please provide a message to encrypt")
            print("Usage: encrypt <message>")
            return
        
        try:
            # Generate key
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)
            
            # Encrypt
            cipher_text = cipher_suite.encrypt(arg.encode())
            
            print(f"\n{'='*60}")
            print("Encryption Successful")
            print(f"{'='*60}")
            print(f"\nEncrypted: {cipher_text.decode()}")
            print(f"\nKey:       {key.decode()}")
            print(f"\n⚠ IMPORTANT: Save the key to decrypt this message!")
            print(f"{'='*60}\n")
            
            # Auto-save key if configured
            if self.config['auto_save_keys']:
                key_id = f"key_{len(self.keys) + 1}"
                self.keys[key_id] = key.decode()
                print(f"✓ Key saved as: {key_id}")
            
            self.logger.info("Message encrypted successfully")
            
        except Exception as e:
            print(f"✗ Error encrypting message: {e}")
            self.logger.error(f"Encryption error: {e}", exc_info=True)
    
    def do_decrypt(self, arg: str) -> None:
        """
        Decrypt a message encrypted with Fernet.
        
        Usage: decrypt <encrypted_message> <key>
        
        Example:
            decrypt gAAAAAB... your_key_here
        """
        args = arg.split(maxsplit=1)
        
        if len(args) != 2:
            print("✗ Error: Invalid arguments")
            print("Usage: decrypt <encrypted_message> <key>")
            return
        
        encrypted_message, key = args
        
        try:
            cipher_suite = Fernet(key.encode())
            plain_text = cipher_suite.decrypt(encrypted_message.encode())
            
            print(f"\n{'='*60}")
            print("Decryption Successful")
            print(f"{'='*60}")
            print(f"\nDecrypted: {plain_text.decode()}")
            print(f"{'='*60}\n")
            
            self.logger.info("Message decrypted successfully")
            
        except Exception as e:
            print(f"✗ Decryption failed: {e}")
            print("\nPossible causes:")
            print("  • Wrong key")
            print("  • Corrupted encrypted message")
            print("  • Invalid format")
            self.logger.error(f"Decryption error: {e}")
    
    # ===== Advanced Encryption =====
    
    def do_encrypt_message(self, arg: str) -> None:
        """
        Encrypt a message with algorithm selection.
        
        Usage: encrypt_message <algorithm> <message>
        
        Algorithms: fernet, aes256
        
        Examples:
            encrypt_message fernet Hello World
            encrypt_message aes256 Secret data
        """
        parts = arg.split(maxsplit=1)
        
        if len(parts) != 2:
            print("Usage: encrypt_message <algorithm> <message>")
            print("Algorithms: fernet, aes256")
            return
        
        algorithm, message = parts
        
        if algorithm.lower() == 'fernet':
            self.do_encrypt(message)
        elif algorithm.lower() == 'aes256':
            self._encrypt_aes256(message)
        else:
            print(f"✗ Error: Unknown algorithm '{algorithm}'")
            print("Available: fernet, aes256")
    
    def _encrypt_aes256(self, message: str) -> None:
        """Encrypt using AES-256-CBC."""
        try:
            # Generate key and IV
            key = os.urandom(32)  # 256 bits
            iv = os.urandom(16)   # 128 bits
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad message to block size (16 bytes)
            padded_message = self._pad_message(message.encode())
            
            # Encrypt
            ciphertext = encryptor.update(padded_message) + encryptor.finalize()
            
            # Encode for display
            encrypted_b64 = base64.b64encode(ciphertext).decode()
            key_b64 = base64.b64encode(key).decode()
            iv_b64 = base64.b64encode(iv).decode()
            
            print(f"\n{'='*60}")
            print("AES-256 Encryption Successful")
            print(f"{'='*60}")
            print(f"\nEncrypted: {encrypted_b64}")
            print(f"\nKey:       {key_b64}")
            print(f"IV:        {iv_b64}")
            print(f"\n⚠ Save both key and IV to decrypt!")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"✗ AES encryption error: {e}")
    
    def do_encrypt_file(self, arg: str) -> None:
        """
        Encrypt a file.
        
        Usage: encrypt_file <input_file> [output_file]
        
        If output_file is not specified, creates <input_file>.encrypted
        
        Example:
            encrypt_file secret.txt
            encrypt_file data.txt encrypted_data.bin
        """
        args = arg.split()
        
        if not args:
            print("Usage: encrypt_file <input_file> [output_file]")
            return
        
        input_file = args[0]
        output_file = args[1] if len(args) > 1 else f"{input_file}.encrypted"
        
        try:
            # Read file
            with open(input_file, 'rb') as f:
                data = f.read()
            
            # Generate key
            key = Fernet.generate_key()
            cipher_suite = Fernet(key)
            
            # Encrypt
            encrypted_data = cipher_suite.encrypt(data)
            
            # Write encrypted file
            with open(output_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Save key
            key_file = f"{output_file}.key"
            with open(key_file, 'wb') as f:
                f.write(key)
            
            print(f"\n✓ File encrypted successfully")
            print(f"  Encrypted file: {output_file}")
            print(f"  Key file:       {key_file}")
            print(f"\n⚠ Keep the key file safe!")
            
            self.logger.info(f"File encrypted: {input_file} -> {output_file}")
            
        except FileNotFoundError:
            print(f"✗ Error: File '{input_file}' not found")
        except Exception as e:
            print(f"✗ Encryption error: {e}")
            self.logger.error(f"File encryption error: {e}", exc_info=True)
    
    def do_decrypt_file(self, arg: str) -> None:
        """
        Decrypt a file.
        
        Usage: decrypt_file <encrypted_file> <key_file> [output_file]
        
        Example:
            decrypt_file data.txt.encrypted data.txt.encrypted.key
            decrypt_file encrypted.bin key.bin decrypted.txt
        """
        args = arg.split()
        
        if len(args) < 2:
            print("Usage: decrypt_file <encrypted_file> <key_file> [output_file]")
            return
        
        encrypted_file = args[0]
        key_file = args[1]
        output_file = args[2] if len(args) > 2 else encrypted_file.replace('.encrypted', '')
        
        try:
            # Read encrypted data
            with open(encrypted_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Read key
            with open(key_file, 'rb') as f:
                key = f.read()
            
            # Decrypt
            cipher_suite = Fernet(key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            
            # Write decrypted file
            with open(output_file, 'wb') as f:
                f.write(decrypted_data)
            
            print(f"\n✓ File decrypted successfully")
            print(f"  Output: {output_file}")
            
            self.logger.info(f"File decrypted: {encrypted_file} -> {output_file}")
            
        except FileNotFoundError as e:
            print(f"✗ Error: File not found - {e}")
        except Exception as e:
            print(f"✗ Decryption error: {e}")
            self.logger.error(f"File decryption error: {e}", exc_info=True)
    
    def do_encrypt_password(self, arg: str) -> None:
        """
        Encrypt message using password-based encryption.
        
        Usage: encrypt_password <password> <message>
        
        Derives encryption key from password using PBKDF2.
        
        Example:
            encrypt_password MySecurePass123 Secret message
        """
        parts = arg.split(maxsplit=1)
        
        if len(parts) != 2:
            print("Usage: encrypt_password <password> <message>")
            return
        
        password, message = parts
        
        try:
            # Generate salt
            salt = os.urandom(16)
            
            # Derive key from password
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=self.config['key_iterations'],
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Encrypt
            cipher_suite = Fernet(key)
            encrypted = cipher_suite.encrypt(message.encode())
            
            # Encode salt and encrypted data
            salt_b64 = base64.b64encode(salt).decode()
            encrypted_b64 = encrypted.decode()
            
            print(f"\n{'='*60}")
            print("Password-Based Encryption Successful")
            print(f"{'='*60}")
            print(f"\nEncrypted: {encrypted_b64}")
            print(f"Salt:      {salt_b64}")
            print(f"\n⚠ Save the salt to decrypt with the same password!")
            print(f"{'='*60}\n")
            
        except Exception as e:
            print(f"✗ Encryption error: {e}")
    
    # ===== Hashing =====
    
    def do_hash(self, arg: str) -> None:
        """
        Generate hash of a message.
        
        Usage: hash <message> [algorithm]
        
        Default algorithm: sha256
        
        Examples:
            hash password123
            hash secret_data md5
            hash "complex message" sha512
        """
        parts = arg.split(maxsplit=1)
        
        if not parts:
            print("Usage: hash <message> [algorithm]")
            print(f"Default algorithm: {self.config['default_algorithm']}")
            return
        
        # Parse arguments
        if len(parts) == 1:
            message = parts[0]
            algorithm = self.config['default_algorithm']
        else:
            # Check if last word is an algorithm
            words = arg.split()
            if words[-1].lower() in self.hash_algorithms:
                algorithm = words[-1].lower()
                message = ' '.join(words[:-1])
            else:
                message = arg
                algorithm = self.config['default_algorithm']
        
        try:
            if algorithm not in self.hash_algorithms:
                print(f"✗ Error: Unknown algorithm '{algorithm}'")
                print(f"Available: {', '.join(self.hash_algorithms.keys())}")
                return
            
            # Generate hash
            hash_func = self.hash_algorithms[algorithm]
            hash_digest = hash_func(message.encode()).hexdigest()
            
            print(f"\n{'='*60}")
            print(f"Hash Generated ({algorithm.upper()})")
            print(f"{'='*60}")
            print(f"\nMessage:  {message}")
            print(f"Hash:     {hash_digest}")
            print(f"Length:   {len(hash_digest)} characters")
            print(f"{'='*60}\n")
            
            self.logger.info(f"Hash generated using {algorithm}")
            
        except Exception as e:
            print(f"✗ Hashing error: {e}")
            self.logger.error(f"Hash generation error: {e}", exc_info=True)
    
    def do_hash_file(self, arg: str) -> None:
        """
        Generate hash of a file.
        
        Usage: hash_file <file_path> [algorithm]
        
        Default algorithm: sha256
        
        Examples:
            hash_file document.pdf
            hash_file image.jpg md5
        """
        parts = arg.split()
        
        if not parts:
            print("Usage: hash_file <file_path> [algorithm]")
            return
        
        file_path = parts[0]
        algorithm = parts[1].lower() if len(parts) > 1 else self.config['default_algorithm']
        
        if algorithm not in self.hash_algorithms:
            print(f"✗ Error: Unknown algorithm '{algorithm}'")
            return
        
        try:
            hash_func = self.hash_algorithms[algorithm]()
            
            # Read file in chunks
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            
            hash_digest = hash_func.hexdigest()
            file_size = Path(file_path).stat().st_size
            
            print(f"\n{'='*60}")
            print(f"File Hash ({algorithm.upper()})")
            print(f"{'='*60}")
            print(f"\nFile:     {file_path}")
            print(f"Size:     {file_size:,} bytes")
            print(f"Hash:     {hash_digest}")
            print(f"{'='*60}\n")
            
            self.logger.info(f"File hashed: {file_path} using {algorithm}")
            
        except FileNotFoundError:
            print(f"✗ Error: File '{file_path}' not found")
        except Exception as e:
            print(f"✗ Error: {e}")
            self.logger.error(f"File hashing error: {e}", exc_info=True)
    
    def do_multi_hash(self, arg: str) -> None:
        """
        Generate multiple hash types for a message.
        
        Usage: multi_hash <message>
        
        Generates MD5, SHA1, SHA256, SHA512 hashes.
        
        Example:
            multi_hash password123
        """
        if not arg:
            print("Usage: multi_hash <message>")
            return
        
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        
        print(f"\n{'='*60}")
        print("Multiple Hash Generation")
        print(f"{'='*60}")
        print(f"\nMessage: {arg}\n")
        
        for algo in algorithms:
            hash_func = self.hash_algorithms[algo]
            digest = hash_func(arg.encode()).hexdigest()
            print(f"{algo.upper():<10} {digest}")
        
        print(f"{'='*60}\n")
    
    def do_crack_hash(self, arg: str) -> None:
        """
        Attempt to crack a hash using a wordlist.
        
        Usage: crack_hash <hash> <algorithm> <wordlist_file>
        
        Example:
            crack_hash 5f4dcc3b5aa765d61d8327deb882cf99 md5 passwords.txt
        """
        parts = arg.split()
        
        if len(parts) != 3:
            print("Usage: crack_hash <hash> <algorithm> <wordlist_file>")
            return
        
        target_hash, algorithm, wordlist = parts
        
        if algorithm.lower() not in self.hash_algorithms:
            print(f"✗ Error: Unknown algorithm '{algorithm}'")
            return
        
        try:
            hash_func = self.hash_algorithms[algorithm.lower()]
            attempts = 0
            found = False
            
            print(f"\n{'='*60}")
            print(f"Hash Cracking ({algorithm.upper()})")
            print(f"{'='*60}")
            print(f"\nTarget hash: {target_hash}")
            print(f"Wordlist:    {wordlist}")
            print(f"\nCracking...")
            
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    attempts += 1
                    
                    # Generate hash
                    test_hash = hash_func(password.encode()).hexdigest()
                    
                    if test_hash == target_hash:
                        found = True
                        print(f"\n✓ HASH CRACKED!")
                        print(f"\nPassword: {password}")
                        print(f"Attempts: {attempts:,}")
                        print(f"{'='*60}\n")
                        
                        self.crack_attempts.append({
                            'hash': target_hash,
                            'algorithm': algorithm,
                            'password': password,
                            'attempts': attempts
                        })
                        
                        self.logger.info(f"Hash cracked in {attempts} attempts")
                        break
                    
                    # Progress indicator
                    if attempts % 10000 == 0:
                        print(f"  Tried {attempts:,} passwords...", end='\r')
            
            if not found:
                print(f"\n✗ Hash not cracked after {attempts:,} attempts")
                print(f"{'='*60}\n")
            
        except FileNotFoundError:
            print(f"✗ Error: Wordlist '{wordlist}' not found")
        except Exception as e:
            print(f"✗ Error: {e}")
            self.logger.error(f"Hash cracking error: {e}", exc_info=True)
    
    def do_compare_hash(self, arg: str) -> None:
        """
        Compare two hash values.
        
        Usage: compare_hash <hash1> <hash2>
        
        Example:
            compare_hash abc123def456 abc123def456
        """
        parts = arg.split()
        
        if len(parts) != 2:
            print("Usage: compare_hash <hash1> <hash2>")
            return
        
        hash1, hash2 = parts
        
        match = hash1 == hash2
        
        print(f"\n{'='*60}")
        print("Hash Comparison")
        print(f"{'='*60}")
        print(f"\nHash 1: {hash1}")
        print(f"Hash 2: {hash2}")
        print(f"\nResult: {'✓ MATCH' if match else '✗ NO MATCH'}")
        print(f"{'='*60}\n")
    
    # ===== Encoding/Decoding =====
    
    def do_base64_encode(self, arg: str) -> None:
        """
        Encode text to Base64.
        
        Usage: base64_encode <text>
        
        Example:
            base64_encode Hello World
        """
        if not arg:
            print("Usage: base64_encode <text>")
            return
        
        encoded = base64.b64encode(arg.encode()).decode()
        print(f"\nOriginal: {arg}")
        print(f"Encoded:  {encoded}\n")
    
    def do_base64_decode(self, arg: str) -> None:
        """
        Decode Base64 text.
        
        Usage: base64_decode <base64_text>
        
        Example:
            base64_decode SGVsbG8gV29ybGQ=
        """
        if not arg:
            print("Usage: base64_decode <base64_text>")
            return
        
        try:
            decoded = base64.b64decode(arg).decode()
            print(f"\nEncoded:  {arg}")
            print(f"Decoded:  {decoded}\n")
        except Exception as e:
            print(f"✗ Decoding error: {e}")
    
    def do_hex_encode(self, arg: str) -> None:
        """
        Encode text to hexadecimal.
        
        Usage: hex_encode <text>
        
        Example:
            hex_encode Hello
        """
        if not arg:
            print("Usage: hex_encode <text>")
            return
        
        encoded = arg.encode().hex()
        print(f"\nOriginal: {arg}")
        print(f"Hex:      {encoded}\n")
    
    def do_hex_decode(self, arg: str) -> None:
        """
        Decode hexadecimal to text.
        
        Usage: hex_decode <hex_string>
        
        Example:
            hex_decode 48656c6c6f
        """
        if not arg:
            print("Usage: hex_decode <hex_string>")
            return
        
        try:
            decoded = bytes.fromhex(arg).decode()
            print(f"\nHex:      {arg}")
            print(f"Decoded:  {decoded}\n")
        except Exception as e:
            print(f"✗ Decoding error: {e}")
    
    # ===== Key Management =====
    
    def do_generate_key(self, arg: str) -> None:
        """
        Generate a new encryption key.
        
        Usage: generate_key [key_id]
        
        Example:
            generate_key mykey
        """
        key = Fernet.generate_key()
        
        if arg:
            key_id = arg.strip()
            self.keys[key_id] = key.decode()
            print(f"✓ Key generated and saved as: {key_id}")
        else:
            print(f"\nGenerated Key: {key.decode()}\n")
    
    def do_save_key(self, arg: str) -> None:
        """
        Save a key to file.
        
        Usage: save_key <key_id> <filename>
        
        Example:
            save_key mykey mykey.key
        """
        parts = arg.split()
        
        if len(parts) != 2:
            print("Usage: save_key <key_id> <filename>")
            return
        
        key_id, filename = parts
        
        if key_id not in self.keys:
            print(f"✗ Error: Key '{key_id}' not found")
            return
        
        try:
            key_path = self.key_dir / filename
            with open(key_path, 'w') as f:
                f.write(self.keys[key_id])
            
            print(f"✓ Key saved to: {key_path}")
        except Exception as e:
            print(f"✗ Error saving key: {e}")
    
    # ===== Utilities =====
    
    def do_algorithms(self, arg: str) -> None:
        """
        Show available algorithms.
        
        Usage: algorithms
        """
        print(f"\n{'='*60}")
        print("Available Hash Algorithms")
        print(f"{'='*60}\n")
        
        for algo in sorted(self.hash_algorithms.keys()):
            print(f"  • {algo}")
        
        print(f"\n{'='*60}\n")
    
    def do_config(self, arg: str) -> None:
        """
        Configure module settings.
        
        Usage: config [key] [value]
               config show
        
        Example:
            config show
            config default_algorithm sha512
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
        
        self.config[key] = value
        print(f"✓ Set {key} = {value}")
    
    # ===== Helper Methods =====
    
    def _pad_message(self, message: bytes) -> bytes:
        """Pad message to AES block size (16 bytes)."""
        block_size = 16
        padding_length = block_size - (len(message) % block_size)
        padding = bytes([padding_length] * padding_length)
        return message + padding
    
    # ===== Exit Commands =====
    
    def do_back(self, arg: str) -> bool:
        """Return to main menu."""
        print("Exiting Encryption/Decryption Module.")
        self.logger.info("Crypto module exited")
        return True
    
    def do_exit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    def do_quit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    # ===== Tab Completion =====
    
    def complete_hash(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for hash command."""
        return [algo for algo in self.hash_algorithms.keys() if algo.startswith(text)]
    
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
    
    print("Running Crypto Module in test mode...")
    EncryptionDecryptionModule().cmdloop()


if __name__ == '__main__':
    main()
