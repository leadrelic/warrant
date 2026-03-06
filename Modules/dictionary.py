"""
Password Dictionary Creator Module
Advanced wordlist generation for penetration testing and password cracking.
"""

import cmd
import itertools
import logging
from pathlib import Path
from typing import List, Dict, Set
import re


class PasswordDictionaryCreator(cmd.Cmd):
    """
    Enhanced password dictionary creator with advanced pattern generation.
    
    Features:
    - Leetspeak substitutions
    - Case permutations
    - Word combinations
    - Special character appending
    - Number patterns
    - Custom rule sets
    - Year variations
    - Common password patterns
    """
    
    prompt = '(dict_creator) '
    intro = '''
╔══════════════════════════════════════════════════════════════╗
║       Password Dictionary Creator Module                     ║
║       Advanced Wordlist Generation Tool                      ║
╚══════════════════════════════════════════════════════════════╝

Type 'help' or '?' to list available commands.
Type 'back' or 'exit' to return to main menu.
'''
    
    def __init__(self):
        """Initialize the dictionary creator module."""
        super().__init__()
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Configuration
        self.config = {
            'max_combinations': 1000000,  # Safety limit
            'include_leetspeak': True,
            'include_case_variations': True,
            'include_word_combos': True,
            'include_year_variations': True,
            'min_word_length': 3,
            'max_word_length': 20
        }
        
        # Pattern definitions
        self.leetspeak_subs = {
            'a': ['@', '4', 'А'],
            'e': ['3', 'Е'],
            'i': ['1', '!', 'І'],
            'o': ['0', 'О'],
            's': ['$', '5', 'Ѕ'],
            't': ['7', '+'],
            'l': ['1', '|'],
            'g': ['9'],
            'b': ['8'],
            'z': ['2']
        }
        
        self.special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '_', '-', '+', '=']
        self.common_numbers = ['1', '12', '123', '1234', '0', '00', '000']
        self.common_years = [str(year) for year in range(1950, 2030)]
        
        # Statistics
        self.stats = {
            'total_generated': 0,
            'unique_passwords': 0,
            'duplicates_skipped': 0
        }
    
    # ===== Core Commands =====
    
    def do_generate(self, arg: str) -> None:
        """
        Generate a password dictionary from base words.
        
        Usage: generate <base_words> <output_file>
        
        Examples:
            generate "password,admin,user" passwords.txt
            generate word1,word2,word3 wordlist.txt
        
        Base words can be comma-separated or space-separated (use quotes for spaces).
        """
        args = arg.split(maxsplit=1)
        
        if len(args) != 2:
            print("✗ Error: Invalid arguments")
            print("Usage: generate <base_words> <output_file>")
            print("\nExamples:")
            print('  generate "password,admin" output.txt')
            print('  generate company,name,2024 wordlist.txt')
            return
        
        # Parse base words
        base_words_str, output_file = args[0], args[1]
        base_words = [w.strip() for w in re.split(r'[,\s]+', base_words_str) if w.strip()]
        
        if not base_words:
            print("✗ Error: No valid base words provided")
            return
        
        # Validate words
        valid_words = []
        for word in base_words:
            if len(word) < self.config['min_word_length']:
                print(f"⚠ Skipping '{word}': too short (min {self.config['min_word_length']} chars)")
                continue
            if len(word) > self.config['max_word_length']:
                print(f"⚠ Skipping '{word}': too long (max {self.config['max_word_length']} chars)")
                continue
            valid_words.append(word)
        
        if not valid_words:
            print("✗ Error: No valid words after filtering")
            return
        
        print(f"\n✓ Generating dictionary with {len(valid_words)} base word(s)...")
        print(f"  Output: {output_file}")
        
        try:
            self.create_dictionary(valid_words, output_file)
            self._print_stats()
        except KeyboardInterrupt:
            print("\n⚠ Generation cancelled by user")
            self.logger.warning("Dictionary generation cancelled")
        except Exception as e:
            print(f"✗ Error: {e}")
            self.logger.error(f"Dictionary generation failed: {e}", exc_info=True)
    
    def do_generate_from_file(self, arg: str) -> None:
        """
        Generate dictionary from a file containing base words.
        
        Usage: generate_from_file <input_file> <output_file>
        
        Input file should contain one word per line.
        
        Example:
            generate_from_file base_words.txt output.txt
        """
        args = arg.split()
        
        if len(args) != 2:
            print("✗ Error: Invalid arguments")
            print("Usage: generate_from_file <input_file> <output_file>")
            return
        
        input_file, output_file = args[0], args[1]
        
        try:
            # Read base words from file
            with open(input_file, 'r', encoding='utf-8') as f:
                base_words = [line.strip() for line in f if line.strip()]
            
            if not base_words:
                print("✗ Error: Input file is empty")
                return
            
            print(f"✓ Loaded {len(base_words)} base word(s) from {input_file}")
            print(f"  Generating dictionary...")
            
            self.create_dictionary(base_words, output_file)
            self._print_stats()
            
        except FileNotFoundError:
            print(f"✗ Error: Input file '{input_file}' not found")
        except Exception as e:
            print(f"✗ Error: {e}")
            self.logger.error(f"File-based generation failed: {e}", exc_info=True)
    
    def do_quick(self, arg: str) -> None:
        """
        Quick generation with common patterns only (faster).
        
        Usage: quick <base_words> <output_file>
        
        Example:
            quick "admin,password" quick_list.txt
        
        Generates fewer variations for faster output.
        """
        args = arg.split(maxsplit=1)
        
        if len(args) != 2:
            print("✗ Error: Invalid arguments")
            print("Usage: quick <base_words> <output_file>")
            return
        
        base_words_str, output_file = args[0], args[1]
        base_words = [w.strip() for w in re.split(r'[,\s]+', base_words_str) if w.strip()]
        
        if not base_words:
            print("✗ Error: No valid base words provided")
            return
        
        print(f"✓ Quick generation with {len(base_words)} base word(s)...")
        
        try:
            self._quick_generate(base_words, output_file)
            self._print_stats()
        except Exception as e:
            print(f"✗ Error: {e}")
    
    def do_config(self, arg: str) -> None:
        """
        Configure dictionary generation settings.
        
        Usage: config [key] [value]
               config show
        
        Available settings:
            max_combinations       - Maximum passwords to generate
            include_leetspeak      - Enable leetspeak substitutions (true/false)
            include_case_variations - Enable case variations (true/false)
            include_word_combos    - Enable word combinations (true/false)
            include_year_variations - Add year suffixes (true/false)
            min_word_length        - Minimum word length
            max_word_length        - Maximum word length
        
        Example:
            config show
            config max_combinations 500000
            config include_leetspeak false
        """
        args = arg.split(maxsplit=1)
        
        if not args or args[0] == 'show':
            print("\n╔══════════════════════════════════════════════════════╗")
            print("║           Current Configuration                      ║")
            print("╚══════════════════════════════════════════════════════╝\n")
            for key, value in sorted(self.config.items()):
                print(f"  {key:.<30} {value}")
            print()
            return
        
        if len(args) < 2:
            print("✗ Error: Usage: config [key] [value] | config show")
            return
        
        key, value = args[0], args[1]
        
        if key not in self.config:
            print(f"✗ Error: Unknown setting '{key}'")
            print("  Use 'config show' to see available settings")
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
        self.logger.info(f"Configuration updated: {key} = {value}")
    
    def do_patterns(self, arg: str) -> None:
        """
        Show available pattern types.
        
        Usage: patterns
        
        Displays leetspeak substitutions, special characters, and other patterns.
        """
        print("\n╔══════════════════════════════════════════════════════╗")
        print("║              Available Patterns                      ║")
        print("╚══════════════════════════════════════════════════════╝\n")
        
        print("Leetspeak Substitutions:")
        for char, subs in sorted(self.leetspeak_subs.items()):
            print(f"  {char} → {', '.join(subs)}")
        
        print(f"\nSpecial Characters: {', '.join(self.special_chars)}")
        print(f"\nCommon Numbers: {', '.join(self.common_numbers)}")
        print(f"\nYear Range: {self.common_years[0]} - {self.common_years[-1]}")
        print()
    
    def do_stats(self, arg: str) -> None:
        """
        Display generation statistics.
        
        Usage: stats
        """
        self._print_stats()
    
    def do_back(self, arg: str) -> bool:
        """Return to main menu."""
        print("Exiting Password Dictionary Creator Module.")
        self.logger.info("Dictionary creator module exited")
        return True
    
    def do_exit(self, arg: str) -> bool:
        """Return to main menu."""
        return self.do_back(arg)
    
    # ===== Helper Methods =====
    
    def create_dictionary(self, base_words: List[str], output_file: str) -> None:
        """Generate comprehensive password dictionary."""
        # Reset statistics
        self.stats = {'total_generated': 0, 'unique_passwords': 0, 'duplicates_skipped': 0}
        seen_passwords = set()
        
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as file:
            for word in base_words:
                print(f"  Processing: {word}...")
                
                # Base word
                self._write_unique(word, file, seen_passwords)
                
                # Leetspeak variations
                if self.config['include_leetspeak']:
                    for leet_word in self._apply_leetspeak(word):
                        self._write_unique(leet_word, file, seen_passwords)
                        self._append_patterns(leet_word, file, seen_passwords)
                
                # Case variations
                if self.config['include_case_variations']:
                    for case_var in self._generate_case_variations(word):
                        self._write_unique(case_var, file, seen_passwords)
                        self._append_patterns(case_var, file, seen_passwords)
                
                # Append common patterns to base word
                self._append_patterns(word, file, seen_passwords)
                
                # Check combination limit
                if self.stats['total_generated'] >= self.config['max_combinations']:
                    print(f"\n⚠ Reached maximum combination limit ({self.config['max_combinations']})")
                    break
            
            # Word combinations
            if self.config['include_word_combos'] and len(base_words) > 1:
                print("  Generating word combinations...")
                self._generate_word_combos(base_words, file, seen_passwords)
        
        print(f"\n✓ Dictionary created: {output_file}")
        self.logger.info(f"Dictionary created with {self.stats['unique_passwords']} unique passwords")
    
    def _quick_generate(self, base_words: List[str], output_file: str) -> None:
        """Quick generation with limited patterns."""
        self.stats = {'total_generated': 0, 'unique_passwords': 0, 'duplicates_skipped': 0}
        seen_passwords = set()
        
        with open(output_file, 'w', encoding='utf-8') as file:
            for word in base_words:
                # Base word
                self._write_unique(word, file, seen_passwords)
                self._write_unique(word.capitalize(), file, seen_passwords)
                self._write_unique(word.upper(), file, seen_passwords)
                
                # Common number suffixes
                for num in ['1', '123', '2024', '!']:
                    self._write_unique(word + num, file, seen_passwords)
                    self._write_unique(word.capitalize() + num, file, seen_passwords)
        
        print(f"✓ Quick dictionary created: {output_file}")
    
    def _apply_leetspeak(self, word: str) -> Set[str]:
        """Apply leetspeak substitutions."""
        results = {word}
        
        for char, substitutions in self.leetspeak_subs.items():
            new_results = set()
            for current_word in results:
                # Keep original
                new_results.add(current_word)
                # Apply each substitution
                for sub in substitutions:
                    new_results.add(current_word.replace(char, sub))
                    new_results.add(current_word.replace(char.upper(), sub))
            results = new_results
            
            # Limit explosion
            if len(results) > 100:
                results = set(list(results)[:100])
        
        return results
    
    def _generate_case_variations(self, word: str) -> Set[str]:
        """Generate case variations."""
        variations = {
            word.lower(),
            word.upper(),
            word.capitalize(),
            word[0].upper() + word[1:].lower() if len(word) > 1 else word.upper(),
        }
        
        # Alternating case
        if len(word) <= 8:  # Limit for performance
            alt1 = ''.join([c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word)])
            alt2 = ''.join([c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(word)])
            variations.add(alt1)
            variations.add(alt2)
        
        return variations
    
    def _append_patterns(self, word: str, file, seen_passwords: Set[str]) -> None:
        """Append common patterns to words."""
        # Special characters
        for char in self.special_chars[:6]:  # Limit to reduce explosion
            self._write_unique(word + char, file, seen_passwords)
            self._write_unique(char + word, file, seen_passwords)
        
        # Common numbers
        for num in self.common_numbers:
            self._write_unique(word + num, file, seen_passwords)
            self._write_unique(num + word, file, seen_passwords)
        
        # Year variations
        if self.config['include_year_variations']:
            for year in self.common_years[::5]:  # Every 5th year to limit
                self._write_unique(word + year, file, seen_passwords)
        
        # Combinations
        for char in ['!', '@', '#']:
            for num in ['1', '123']:
                self._write_unique(word + num + char, file, seen_passwords)
                self._write_unique(word + char + num, file, seen_passwords)
    
    def _generate_word_combos(self, base_words: List[str], file, seen_passwords: Set[str]) -> None:
        """Generate word combinations."""
        # Limit combinations for performance
        for combo in itertools.permutations(base_words[:5], min(2, len(base_words))):
            if self.stats['total_generated'] >= self.config['max_combinations']:
                break
            
            concatenated = ''.join(combo)
            self._write_unique(concatenated, file, seen_passwords)
            self._write_unique(concatenated.capitalize(), file, seen_passwords)
            
            # With separators
            for sep in ['', '-', '_', '.']:
                joined = sep.join(combo)
                self._write_unique(joined, file, seen_passwords)
    
    def _write_unique(self, password: str, file, seen_passwords: Set[str]) -> None:
        """Write password if unique."""
        self.stats['total_generated'] += 1
        
        if password not in seen_passwords:
            file.write(password + '\n')
            seen_passwords.add(password)
            self.stats['unique_passwords'] += 1
        else:
            self.stats['duplicates_skipped'] += 1
    
    def _print_stats(self) -> None:
        """Print generation statistics."""
        print("\n╔══════════════════════════════════════════════════════╗")
        print("║              Generation Statistics                   ║")
        print("╚══════════════════════════════════════════════════════╝\n")
        print(f"  Total Generated:      {self.stats['total_generated']:,}")
        print(f"  Unique Passwords:     {self.stats['unique_passwords']:,}")
        print(f"  Duplicates Skipped:   {self.stats['duplicates_skipped']:,}")
        print()
    
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
    
    print("Running Dictionary Creator in test mode...")
    PasswordDictionaryCreator().cmdloop()


if __name__ == '__main__':
    main()
