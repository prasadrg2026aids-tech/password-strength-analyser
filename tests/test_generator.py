import string
import unittest
from unittest.mock import patch

import generator
from generator import AMBIGUOUS_CHARACTERS, generate_passphrase, generate_password, generate_passwords


class PasswordGeneratorTests(unittest.TestCase):
    def test_generated_values_meet_selected_category_requirements(self):
        for _ in range(10):
            password = generate_password(24, exclude_ambiguous=True)
            self.assertEqual(len(password), 24)
            self.assertTrue(any(char in string.ascii_uppercase for char in password))
            self.assertTrue(any(char in string.ascii_lowercase for char in password))
            self.assertTrue(any(char in string.digits for char in password))
            self.assertTrue(any(char in string.punctuation for char in password))
            self.assertTrue(set(password).isdisjoint(AMBIGUOUS_CHARACTERS))

    def test_single_selected_category_works(self):
        password = generate_password(8, uppercase=False, lowercase=False, numbers=True, symbols=False)
        self.assertTrue(password.isdigit())

    def test_generator_uses_secrets_choice(self):
        with patch("generator.secrets.choice", wraps=generator.secrets.choice) as secure_choice:
            generate_password(12)
        self.assertGreaterEqual(secure_choice.call_count, 4)

    def test_multiple_generation_is_bounded(self):
        self.assertEqual(len(generate_passwords(10, length=8, symbols=False)), 10)
        with self.assertRaises(ValueError):
            generate_passwords(11)

    def test_invalid_length_and_empty_category_selection_rejected(self):
        for length in (7, 65, True):
            with self.subTest(length=length), self.assertRaises(ValueError):
                generate_password(length)
        with self.assertRaises(ValueError):
            generate_password(12, uppercase=False, lowercase=False, numbers=False, symbols=False)

    def test_passphrase_options(self):
        phrase = generate_passphrase(4, separator=".", capitalize=True, add_number=True)
        words = phrase.split(".")
        self.assertEqual(len(words), 5)
        self.assertTrue(all(word[0].isupper() for word in words[:4]))
        self.assertTrue(words[-1].isdigit())
        with self.assertRaises(ValueError):
            generate_passphrase(2)


if __name__ == "__main__":
    unittest.main()
