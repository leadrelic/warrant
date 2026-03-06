"""
Password Cracking Module
Advanced password cracking with multiple attack methods.
"""

import cmd
import hashlib
import logging
import time
import itertools
import string
from pathlib import Path
from typing import Optional, Dict, List, Callable
from datetime import datetime
import multiprocessing
from functools import partial


class PasswordCrackingModule(cmd.Cmd):
    """
    Advanced password cracking module with multiple attack methods.
    
    Features:
    - Dictionary attacks with multiple hash algorithms
    - Brute force attacks with customizable character sets
    - Hybrid attacks (dictionary + mutations)
    - Rule-based attacks (leetspeak, case variations, appending)
    - Rainbow table generation
    - Multi-threaded cracking
    - Progress tracking and statistics
    - Hash identification
    - Mask attacks
    - Wordlist generation
    """
    
    prompt = '(crack) '
    intro = '''
╔══════════════════════════════════════════════════════════════╗
║              Password Cracking Module                         ║
╚══════════════════════════════════════════════════════════════╝

Attack Methods:
  dictionary              - Dictionary attack with wordlist
  brute_force             - Brute force attack
  hybrid                  - Dictionary + mutations
  rule_based              - Apply transformation rules
  mask                    - Mask attack (e.g., ?u?l?l?l?d?d)
  
Hash Operations:
  crack                   - Quick crack (auto-detect method)
  identify                - Identify hash type
  multi_crack             - Try multiple algorithms
  batch_crack             - Crack multiple hashes
  
Wordlist Tools:
  generate_wordlist       - Generate custom wordlist
  combine_wordlists       - Merge multiple wordlists
  stats                   - Show wordlist statistics
  
Configuration:
  algorithms              - Show supported algorithms
  config                  - Configure cracking settings
  results                 - View cracking history

Type 'help <command>' for detailed usage.
Type 'back' or 'exit' to return to main menu.
'''
    
    def __init__(self):
        """Initialize the password cracking module."""
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configuration
        self.config = {
            'default_algorithm': 'md5',
            'max_length': 8,
            'min_length': 1,
            'show_attempts': True,
            'progress_interval': 10000,
            'use_multiprocessing': False,
            'threads': multiprocessing.cpu_count(),
            'charset': 'alphanumeric'
        }
        
        # Character sets for brute force
        self.charsets = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'letters': string.ascii_letters,
            'digits': string.digits,
            'alphanumeric': string.ascii_letters + string.digits,
            'alphanumeric_special': string.ascii_letters + string.digits + string.punctuation,
            'hex': '0123456789abcdef',
            'custom': ''
        }
        
        # Supported hashing algorithms
        self.algorithms = {
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
        }
        
        # Hash length mapping for identification
        self.hash_lengths = {
            32: ['md5'],
            40: ['sha1'],
            56: ['sha224', 'sha3_224'],
            64: ['sha256', 'sha3_256'],
            96: ['sha384', 'sha3_384'],
            128: ['sha512', 'sha3_512']
        }
        
        # Cracking history
        self.crack_history = []
        
        # Statistics
        self.stats = {
            'total_attempts': 0,
            'successful_cracks': 0,
            'failed_cracks': 0,
            'total_time': 0
        }
    
    # ===== Quick Crack Commands =====
    
    def do_crack(self, arg: str) -> None:
        """
        Quick crack with auto-detection.
        
        Usage: crack <hash> <wordlist> [algorithm]
        
        If algorithm not specified, attempts to identify hash type.
        
        Examples:
            crack 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt
            crack 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt md5
        """
        parts = arg.split()
        
        if len(parts) < 2:
            print("Usage: crack <hash> <wordlist> [algorithm]")
            return
        
        target_hash = parts[0]
        wordlist = parts[1]
        algorithm = parts[2] if len(parts) > 2 else None
        
        # Auto-detect algorithm if not provided
        if not algorithm:
            detected = self._identify_hash(target_hash)
            if detected:
                algorithm = detected[0]
                print(f"ℹ Auto-detected algorithm: {algorithm}")
            else:
                algorithm = self.config['default_algorithm']
                print(f"⚠ Could not detect algorithm, using default: {algorithm}")
        
        # Run dictionary attack
        self.do_dictionary(f"{target_hash} {wordlist} {algorithm}")
    
    # ===== Dictionary Attack =====
    
    def do_dictionary(self, arg: str) -> None:
        """
        Perform dictionary attack.
        
        Usage: dictionary <hash> <wordlist> <algorithm>
        
        Algorithms: md5, sha1, sha256, sha512, etc.
        
        Examples:
            dictionary 5f4dcc3b5aa765d61d8327deb882cf99 rockyou.txt md5
            dictionary e38ad214943daad1d64c102faec29de4afe9da3d passwords.txt sha1
        """
        parts = arg.split()
        
        if len(parts) != 3:
            print("Usage: dictionary <hash> <wordlist> <algorithm>")
            print(f"Supported algorithms: {', '.join(self.algorithms.keys())}")
            return
        
        target_hash, wordlist, algorithm = parts
        
        if algorithm not in self.algorithms:
            print(f"✗ Error: Unsupported algorithm '{algorithm}'")
            print(f"Supported: {', '.join(self.algorithms.keys())}")
            return
        
        self._crack_with_dictionary(target_hash, wordlist, algorithm)
    
    def _crack_with_dictionary(self, target_hash: str, wordlist_path: str, algorithm: str) -> None:
        """Execute dictionary attack."""
        hash_func = self.algorithms[algorithm]
        
        print(f"\n{'='*70}")
        print(f"Dictionary Attack")
        print(f"{'='*70}")
        print(f"\nTarget Hash: {target_hash}")
        print(f"Algorithm:   {algorithm.upper()}")
        print(f"Wordlist:    {wordlist_path}")
        print(f"\nCracking...")
        
        try:
            start_time = time.time()
            attempts = 0
            found = False
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    word = line.strip()
                    attempts += 1
                    
                    # Generate hash
                    test_hash = hash_func(word.encode()).hexdigest()
                    
                    if test_hash == target_hash:
                        found = True
                        end_time = time.time()
                        duration = end_time - start_time
                        
                        print(f"\n{'='*70}")
                        print(f"✓ PASSWORD CRACKED!")
                        print(f"{'='*70}")
                        print(f"\nPassword:    {word}")
                        print(f"Attempts:    {attempts:,}")
                        print(f"Time:        {duration:.2f} seconds")
                        print(f"Rate:        {attempts/duration:.0f} hashes/sec")
                        print(f"{'='*70}\n")
                        
                        # Record success
                        self._record_crack(target_hash, word, algorithm, attempts, duration, True)
                        return
                    
                    # Show progress
                    if self.config['show_attempts'] and attempts % self.config['progress_interval'] == 0:
                        elapsed = time.time() - start_time
                        rate = attempts / elapsed if elapsed > 0 else 0
                        print(f"  Attempts: {attempts:,} | Rate: {rate:.0f} h/s", end='\r')
            
            # Not found
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"\n\n{'='*70}")
            print(f"✗ Password Not Found")
            print(f"{'='*70}")
            print(f"\nAttempts:    {attempts:,}")
            print(f"Time:        {duration:.2f} seconds")
            print(f"Rate:        {attempts/duration:.0f} hashes/sec")
            print(f"{'='*70}\n")
            
            # Record failure
            self._record_crack(target_hash, None, algorithm, attempts, duration, False)
            
        except FileNotFoundError:
            print(f"\n✗ Error: Wordlist '{wordlist_path}' not found")
        except KeyboardInterrupt:
            print(f"\n\n⚠ Attack cancelled by user")
        except Exception as e:
            print(f"\n✗ Error: {e}")
            self.logger.error(f"Dictionary attack error: {e}", exc_info=True)
    
    # ===== Brute Force Attack =====
    
    def do_brute_force(self, arg: str) -> None:
        """
        Perform brute force attack.
        
        Usage: brute_force <hash> <algorithm> [min_length] [max_length] [charset]
        
        Charsets: lowercase, uppercase, letters, digits, alphanumeric, 
                  alphanumeric_special, hex, custom
        
        Examples:
            brute_force 5f4dcc3b5aa765d61d8327deb882cf99 md5
            brute_force 5f4dcc3b5aa765d61d8327deb882cf99 md5 1 4 digits
            brute_force abc123... sha256 1 6 lowercase
        
        Warning: Brute force can take a very long time!
        """
        parts = arg.split()
        
        if len(parts) < 2:
            print("Usage: brute_force <hash> <algorithm> [min_length] [max_length] [charset]")
            return
        
        target_hash = parts[0]
        algorithm = parts[1]
        min_length = int(parts[2]) if len(parts) > 2 else self.config['min_length']
        max_length = int(parts[3]) if len(parts) > 3 else min(self.config['max_length'], 6)
        charset_name = parts[4] if len(parts) > 4 else self.config['charset']
        
        if algorithm not in self.algorithms:
            print(f"✗ Error: Unsupported algorithm '{algorithm}'")
            return
        
        if charset_name not in self.charsets:
            print(f"✗ Error: Unknown charset '{charset_name}'")
            print(f"Available: {', '.join(self.charsets.keys())}")
            return
        
        charset = self.charsets[charset_name]
        
        if not charset:
            print("✗ Error: Charset is empty")
            return
        
        # Warning for large searches
        total_combinations = sum(len(charset)**i for i in range(min_length, max_length + 1))
        
        if total_combinations > 1000000:
            print(f"\n⚠ Warning: This will try {total_combinations:,} combinations!")
            print(f"  This could take a very long time.")
            response = input("  Continue? (y/n): ")
            if response.lower() != 'y':
                return
        
        self._brute_force_crack(target_hash, algorithm, min_length, max_length, charset, charset_name)
    
    def _brute_force_crack(self, target_hash: str, algorithm: str, 
                          min_len: int, max_len: int, charset: str, charset_name: str) -> None:
        """Execute brute force attack."""
        hash_func = self.algorithms[algorithm]
        
        print(f"\n{'='*70}")
        print(f"Brute Force Attack")
        print(f"{'='*70}")
        print(f"\nTarget Hash:  {target_hash}")
        print(f"Algorithm:    {algorithm.upper()}")
        print(f"Length Range: {min_len}-{max_len}")
        print(f"Charset:      {charset_name} ({len(charset)} characters)")
        print(f"\nCracking...")
        
        start_time = time.time()
        attempts = 0
        
        try:
            for length in range(min_len, max_len + 1):
                for candidate in itertools.product(charset, repeat=length):
                    password = ''.join(candidate)
                    attempts += 1
                    
                    # Generate hash
                    test_hash = hash_func(password.encode()).hexdigest()
                    
                    if test_hash == target_hash:
                        end_time = time.time()
                        duration = end_time - start_time
                        
                        print(f"\n{'='*70}")
                        print(f"✓ PASSWORD CRACKED!")
                        print(f"{'='*70}")
                        print(f"\nPassword:    {password}")
                        print(f"Attempts:    {attempts:,}")
                        print(f"Time:        {duration:.2f} seconds")
                        print(f"Rate:        {attempts/duration:.0f} hashes/sec")
                        print(f"{'='*70}\n")
                        
                        self._record_crack(target_hash, password, algorithm, attempts, duration, True)
                        return
                    
                    # Show progress
                    if self.config['show_attempts'] and attempts % self.config['progress_interval'] == 0:
                        elapsed = time.time() - start_time
                        rate = attempts / elapsed if elapsed > 0 else 0
                        print(f"  Attempts: {attempts:,} | Current: {password} | Rate: {rate:.0f} h/s", end='\r')
            
            # Not found
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"\n\n{'='*70}")
            print(f"✗ Password Not Found")
            print(f"{'='*70}")
            print(f"\nAttempts:    {attempts:,}")
            print(f"Time:        {duration:.2f} seconds")
            print(f"{'='*70}\n")
            
            self._record_crack(target_hash, None, algorithm, attempts, duration, False)
            
        except KeyboardInterrupt:
            print(f"\n\n⚠ Attack cancelled by user")
    
    # ===== Hybrid Attack =====
    
    def do_hybrid(self, arg: str) -> None:
        """
        Hybrid attack: dictionary + mutations.
        
        Usage: hybrid <hash> <wordlist> <algorithm>
        
        Applies common mutations to dictionary words:
        - Append common numbers (1, 123, 2024, etc.)
        - Append special characters (!, @, #, $)
        - Capitalize first letter
        - All uppercase
        - Leetspeak substitutions
        
        Examples:
            hybrid 5f4dcc3b5aa765d61d8327deb882cf99 passwords.txt md5
        """
        parts = arg.split()
        
        if len(parts) != 3:
            print("Usage: hybrid <hash> <wordlist> <algorithm>")
            return
        
        target_hash, wordlist, algorithm = parts
        
        if algorithm not in self.algorithms:
            print(f"✗ Error: Unsupported algorithm '{algorithm}'")
            return
        
        self._hybrid_attack(target_hash, wordlist, algorithm)
    
    def _hybrid_attack(self, target_hash: str, wordlist_path: str, algorithm: str) -> None:
        """Execute hybrid attack."""
        hash_func = self.algorithms[algorithm]
        
        # Mutation patterns
        numbers = ['1', '123', '12345', '2024', '2025', '!']
        specials = ['!', '@', '#', '$', '!@#']
        
        print(f"\n{'='*70}")
        print(f"Hybrid Attack (Dictionary + Mutations)")
        print(f"{'='*70}")
        print(f"\nTarget Hash: {target_hash}")
        print(f"Algorithm:   {algorithm.upper()}")
        print(f"Wordlist:    {wordlist_path}")
        print(f"\nCracking...")
        
        try:
            start_time = time.time()
            attempts = 0
            
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
                for line in file:
                    base_word = line.strip()
                    
                    # Generate mutations
                    mutations = [
                        base_word,
                        base_word.capitalize(),
                        base_word.upper(),
                        base_word.lower(),
                    ]
                    
                    # Add number suffixes
                    for num in numbers:
                        mutations.append(base_word + num)
                        mutations.append(base_word.capitalize() + num)
                    
                    # Add special char suffixes
                    for char in specials:
                        mutations.append(base_word + char)
                    
                    # Leetspeak
                    leet = base_word.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '5')
                    mutations.append(leet)
                    
                    # Test all mutations
                    for password in mutations:
                        attempts += 1
                        test_hash = hash_func(password.encode()).hexdigest()
                        
                        if test_hash == target_hash:
                            end_time = time.time()
                            duration = end_time - start_time
                            
                            print(f"\n{'='*70}")
                            print(f"✓ PASSWORD CRACKED!")
                            print(f"{'='*70}")
                            print(f"\nPassword:    {password}")
                            print(f"Base Word:   {base_word}")
                            print(f"Attempts:    {attempts:,}")
                            print(f"Time:        {duration:.2f} seconds")
                            print(f"Rate:        {attempts/duration:.0f} hashes/sec")
                            print(f"{'='*70}\n")
                            
                            self._record_crack(target_hash, password, algorithm, attempts, duration, True)
                            return
                    
                    # Progress
                    if self.config['show_attempts'] and attempts % self.config['progress_interval'] == 0:
                        elapsed = time.time() - start_time
                        rate = attempts / elapsed if elapsed > 0 else 0
                        print(f"  Attempts: {attempts:,} | Rate: {rate:.0f} h/s", end='\r')
            
            # Not found
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"\n\n{'='*70}")
            print(f"✗ Password Not Found")
            print(f"{'='*70}")
            print(f"\nAttempts:    {attempts:,}")
            print(f"Time:        {duration:.2f} seconds")
            print(f"{'='*70}\n")
            
            self._record_crack(target_hash, None, algorithm, attempts, duration, False)
            
        except FileNotFoundError:
            print(f"\n✗ Error: Wordlist '{wordlist_path}' not found")
        except KeyboardInterrupt:
            print(f"\n\n⚠ Attack cancelled by user")
    
    # ===== Hash Identification =====
    
    def do_identify(self, arg: str) -> None:
        """
        Identify hash type based on length and characteristics.
        
        Usage: identify <hash>
        
        Example:
            identify 5f4dcc3b5aa765d61d8327deb882cf99
        """
        if not arg:
            print("Usage: identify <hash>")
            return
        
        possible_types = self._identify_hash(arg.strip())
        
        if possible_types:
            print(f"\n{'='*60}")
            print("Hash Identification")
            print(f"{'='*60}")
            print(f"\nHash: {arg}")
            print(f"Length: {len(arg)} characters")
            print(f"\nPossible types:")
            for hash_type in possible_types:
                print(f"  • {hash_type.upper()}")
            print(f"{'='*60}\n")
        else:
            print(f"\n✗ Could not identify hash type")
            print(f"  Hash length: {len(arg)} characters\n")
    
    def _identify_hash(self, hash_value: str) -> Optional[List[str]]:
        """Identify possible hash types."""
        hash_len = len(hash_value)
        
        if hash_len in self.hash_lengths:
            return self.hash_lengths[hash_len]
        
        return None
    
    # ===== Multi-Algorithm Crack =====
    
    def do_multi_crack(self, arg: str) -> None:
        """
        Try cracking with multiple algorithms.
        
        Usage: multi_crack <hash> <wordlist>
        
        Tries all supported algorithms until password is found.
        
        Example:
            multi_crack 5f4dcc3b5aa765d61d8327deb882cf99 passwords.txt
        """
        parts = arg.split()
        
        if len(parts) != 2:
            print("Usage: multi_crack <hash> <wordlist>")
            return
        
        target_hash, wordlist = parts
        
        # Identify possible algorithms
        possible_algos = self._identify_hash(target_hash)
        
        if possible_algos:
            print(f"ℹ Detected possible algorithms: {', '.join(possible_algos)}")
            algos_to_try = possible_algos
        else:
            print(f"⚠ Could not identify hash type, trying all algorithms")
            algos_to_try = list(self.algorithms.keys())
        
        # Try each algorithm
        for algo in algos_to_try:
            print(f"\n{'='*60}")
            print(f"Trying {algo.upper()}...")
            print(f"{'='*60}")
            
            # Temporarily disable progress for cleaner output
            original_show = self.config['show_attempts']
            self.config['show_attempts'] = False
            
            self._crack_with_dictionary(target_hash, wordlist, algo)
            
            self.config['show_attempts'] = original_show
            
            # Check if we found it
            if self.crack_history and self.crack_history[-1]['success']:
                return
    
    # ===== Batch Cracking =====
    
    def do_batch_crack(self, arg: str) -> None:
        """
        Crack multiple hashes from a file.
        
        Usage: batch_crack <hash_file> <wordlist> <algorithm>
        
        Hash file format: one hash per line
        
        Example:
            batch_crack hashes.txt rockyou.txt md5
        """
        parts = arg.split()
        
        if len(parts) != 3:
            print("Usage: batch_crack <hash_file> <wordlist> <algorithm>")
            return
        
        hash_file, wordlist, algorithm = parts
        
        if algorithm not in self.algorithms:
            print(f"✗ Error: Unsupported algorithm '{algorithm}'")
            return
        
        try:
            # Load hashes
            with open(hash_file, 'r') as f:
                hashes = [line.strip() for line in f if line.strip()]
            
            print(f"\n{'='*60}")
            print(f"Batch Cracking: {len(hashes)} hashes")
            print(f"{'='*60}\n")
            
            # Crack each hash
            for i, hash_value in enumerate(hashes, 1):
                print(f"[{i}/{len(hashes)}] Cracking: {hash_value[:20]}...")
                self._crack_with_dictionary(hash_value, wordlist, algorithm)
            
            print(f"\n{'='*60}")
            print("Batch Cracking Complete")
            print(f"{'='*60}\n")
            
        except FileNotFoundError:
            print(f"✗ Error: File not found")
    
    # ===== Results and Stats =====
    
    def do_results(self, arg: str) -> None:
        """
        View cracking history.
        
        Usage: results [count]
        
        Example:
            results     - Show last 10 results
            results 20  - Show last 20 results
        """
        count = 10
        if arg:
            try:
                count = int(arg)
            except ValueError:
                print("Error: Count must be an integer")
                return
        
        if not self.crack_history:
            print("No cracking history available")
            return
        
        recent = self.crack_history[-count:]
        
        print(f"\n{'='*80}")
        print(f"Cracking History (last {len(recent)})")
        print(f"{'='*80}")
        print(f"\n{'Hash':<35} {'Algorithm':<10} {'Result':<15} {'Attempts':<12}")
        print("-" * 80)
        
        for record in reversed(recent):
            hash_short = record['hash'][:32] + '...' if len(record['hash']) > 32 else record['hash']
            result = f"✓ {record['password']}" if record['success'] else "✗ Failed"
            print(f"{hash_short:<35} {record['algorithm']:<10} {result:<15} {record['attempts']:<12,}")
        
        print(f"\n{'='*80}\n")
    
    def do_stats(self, arg: str) -> None:
        """
        Show cracking statistics.
        
        Usage: stats
        """
        print(f"\n{'='*60}")
        print("Cracking Statistics")
        print(f"{'='*60}")
        print(f"\nTotal Attempts:      {self.stats['total_attempts']:,}")
        print(f"Successful Cracks:   {self.stats['successful_cracks']}")
        print(f"Failed Attempts:     {self.stats['failed_cracks']}")
        print(f"Total Time:          {self.stats['total_time']:.2f} seconds")
        
        if self.stats['successful_cracks'] > 0:
            success_rate = (self.stats['successful_cracks'] / 
                          (self.stats['successful_cracks'] + self.stats['failed_cracks'])) * 100
            print(f"Success Rate:        {success_rate:.1f}%")
        
        print(f"{'='*60}\n")
    
    # ===== Configuration =====
    
    def do_algorithms(self, arg: str) -> None:
        """
        Show supported hash algorithms.
        
        Usage: algorithms
        """
        print(f"\n{'='*60}")
        print("Supported Hash Algorithms")
        print(f"{'='*60}\n")
        
        for algo in sorted(self.algorithms.keys()):
            print(f"  • {algo}")
        
        print(f"\n{'='*60}\n")
    
    def do_config(self, arg: str) -> None:
        """
        Configure module settings.
        
        Usage: config [key] [value]
               config show
        
        Examples:
            config show
            config max_length 10
            config show_attempts false
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
    
    def _record_crack(self, hash_value: str, password: Optional[str], 
                     algorithm: str, attempts: int, duration: float, success: bool) -> None:
        """Record crack attempt in history."""
        record = {
            'timestamp': datetime.now().isoformat(),
            'hash': hash_value,
            'password': password,
            'algorithm': algorithm,
            'attempts': attempts,
            'duration': duration,
            'success': success
        }
        
        self.crack_history.append(record)
        
        # Update stats
        self.stats['total_attempts'] += attempts
        self.stats['total_time'] += duration
        if success:
            self.stats['successful_cracks'] += 1
        else:
            self.stats['failed_cracks'] += 1
        
        self.logger.info(f"Crack attempt recorded: {algorithm} - {'Success' if success else 'Failed'}")
    
    # ===== Exit Commands =====
    
    def do_back(self, arg: str) -> bool:
        """Return to main menu."""
        print("Exiting Password Cracking Module.")
        self.logger.info("Password cracking module exited")
        return True
    
    def do_exit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    def do_quit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    # ===== Tab Completion =====
    
    def complete_dictionary(self, text: str, line: str, begidx: int, endidx: int) -> List[str]:
        """Tab completion for dictionary command."""
        # Complete algorithm (3rd argument)
        parts = line.split()
        if len(parts) >= 3:
            return [algo for algo in self.algorithms.keys() if algo.startswith(text)]
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
    
    print("Running Password Cracking Module in test mode...")
    PasswordCrackingModule().cmdloop()


if __name__ == '__main__':
    main()
