import hashlib
import cmd
import time

class PasswordCrackingModule(cmd.Cmd):
    prompt = '(password_cracking) '
    intro = 'Password Cracking Module. Type help or ? to list commands.\n'

    # Supported hashing algorithms
    supported_algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }

    def do_crack_hash(self, arg):
        """Crack a hash using a dictionary attack.
        Usage: crack_hash <hash> <path_to_dictionary> <algorithm>"""
        args = arg.split()
        if len(args) != 3:
            print("Usage: crack_hash <hash> <path_to_dictionary> <algorithm>")
            return
        target_hash, dict_path, algorithm = args
        if algorithm not in self.supported_algorithms:
            print(f"Unsupported algorithm. Supported algorithms are: {', '.join(self.supported_algorithms.keys())}")
            return
        self.crack_hash_with_dict(target_hash, dict_path, algorithm)

    def do_quit(self, arg):
        """Return to the main menu."""
        print("Exiting Password Cracking Module.")
        return True

    def crack_hash_with_dict(self, target_hash, dict_path, algorithm):
        """Attempt to crack the given hash using a dictionary file and the specified hashing algorithm."""
        hash_func = self.supported_algorithms[algorithm]
        try:
            with open(dict_path, 'r', encoding='utf-8') as file:
                start_time = time.time()
                for count, line in enumerate(file, 1):
                    word = line.strip()
                    if hash_func(word.encode()).hexdigest() == target_hash:
                        print(f"Password found: {word}")
                        print(f"Total attempts: {count}")
                        break
                else:  # This else corresponds to the for loop's completion without break.
                    print("Password not found in dictionary.")
                end_time = time.time()
                print(f"Time taken: {end_time - start_time:.2f} seconds")
        except FileNotFoundError:
            print(f"Dictionary file not found: {dict_path}")
