import unittest

from analyser import analyze_password, estimate_entropy
from generator import generate_passphrase, generate_password
from patterns import detect_patterns


class PasswordAnalyserTests(unittest.TestCase):
    def test_common_and_predictable_passwords_are_capped(self):
        for password in ("password123", "Admin123", "P@ssword123"):
            with self.subTest(password=password):
                result = analyze_password(password)
                self.assertLessEqual(result.score, 20)
                self.assertIn("common password", " ".join(result.weaknesses).lower())

    def test_pattern_detection_covers_sequences_repeats_keyboard_and_segments(self):
        cases = {
            "abcDEF123": "sequence",
            "aaaaaaQ9!": "repeated",
            "qwertyX8!": "keyboard",
            "abcabcX9!": "segment",
        }
        for password, phrase in cases.items():
            with self.subTest(password=password):
                self.assertTrue(any(phrase in finding.lower() for finding in detect_patterns(password)))

    def test_substitutions_are_reported(self):
        self.assertTrue(any("substitution" in item.lower() for item in detect_patterns("P@ssw0rd")))

    def test_score_range_and_checklist(self):
        for password in ("", "123456", "correct-horse-battery-staple", "A8!sGk2#pL9@"):
            result = analyze_password(password)
            self.assertGreaterEqual(result.score, 0)
            self.assertLessEqual(result.score, 100)
            self.assertIn("At least 8 characters", result.checklist)

    def test_strong_generated_password_and_long_passphrase(self):
        generated = analyze_password(generate_password(32))
        passphrase = analyze_password(generate_passphrase(5))
        self.assertGreaterEqual(generated.score, 61)
        self.assertGreaterEqual(passphrase.score, 41)
        self.assertGreaterEqual(passphrase.score, 0)
        self.assertLessEqual(passphrase.score, 100)

    def test_repetition_reduces_entropy_estimate(self):
        self.assertEqual(estimate_entropy("aaaaaaaa"), 0.0)

    def test_non_string_is_rejected(self):
        with self.assertRaises(TypeError):
            analyze_password(None)


if __name__ == "__main__":
    unittest.main()
