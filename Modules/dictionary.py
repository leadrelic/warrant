import itertools
import cmd


class PasswordDictionaryCreator(cmd.Cmd):
    prompt = '(password_dict_creator) '
    intro = 'Enhanced Password Dictionary Creator Module. Type help or ? to list commands.\n'

    def do_generate(self, arg):
        """Generate a complex password dictionary.
        Usage: generate <base_word_list> <output_file_path>"""
        args = arg.split()
        if len(args) != 2:
            print("Usage: generate <base_word_list> <output_file_path>")
            return
        base_word_list, output_file_path = args[0], args[1]
        self.create_dictionary(base_word_list.split(','), output_file_path)

    def do_quit(self, arg):
        """Return to the main menu."""
        print("Exiting Password Dictionary Creator Module.")
        return True

    def create_dictionary(self, base_words, output_file_path):
        """Generate the password dictionary with enhanced patterns."""
        substitutions = {'a': ['@', '4'], 's': ['$'], 'i': ['1'], 'o': ['0']}
        special_chars = ['!', '@', '#', '$']
        numbers = [str(i) for i in range(10)]

        with open(output_file_path, 'w') as file:
            for word in base_words:
                # Generate all substitution combinations
                for sub_word in self.apply_substitutions(word, substitutions):
                    file.write(sub_word + '\n')
                    self.append_special_chars_and_numbers(sub_word, file, special_chars, numbers)

                # Generate permutations of case sensitivity
                for case_permutation in map(''.join, itertools.product(*((c.upper(), c.lower()) for c in word))):
                    file.write(case_permutation + '\n')
                    self.append_special_chars_and_numbers(case_permutation, file, special_chars, numbers)

                # Generate combinations of words
                for combo in itertools.permutations(base_words, 2):
                    concatenated_word = ''.join(combo)
                    file.write(concatenated_word + '\n')
                    self.append_special_chars_and_numbers(concatenated_word, file, special_chars, numbers)

        print(f"Enhanced dictionary created at: {output_file_path}")

    def apply_substitutions(self, word, substitutions):
        """Recursively apply substitutions to generate all possible variations."""
        if word == '':
            return ['']
        else:
            first, rest = word[0], word[1:]
            rest_subbed = self.apply_substitutions(rest, substitutions)
            results = []
            if first.lower() in substitutions:
                for sub in substitutions[first.lower()]:
                    results.extend([sub + rest for rest in rest_subbed])
            results.extend([first + rest for rest in rest_subbed])
            return results

    def append_special_chars_and_numbers(self, word, file, special_chars, numbers):
        """Append/prepend special characters and numbers to a word."""
        for char in special_chars + numbers:
            file.write(word + char + '\n')
            file.write(char + word + '\n')
        # Generate combinations with numbers and special characters
        for combo in itertools.product(special_chars + numbers, repeat=2):
            file.write(word + ''.join(combo) + '\n')
            file.write(''.join(combo) + word + '\n')

