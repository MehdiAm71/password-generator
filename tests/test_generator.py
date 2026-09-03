"""Run with: python -m unittest tests/test_generator.py -v"""

import string
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from password_generator import (
    PasswordPolicy,
    generate_password,
    generate_personalized_password,
    generate_passphrase,
    estimate_strength,
)


class TestPasswordPolicy(unittest.TestCase):
    def test_charset_all_enabled(self):
        policy = PasswordPolicy()
        charset = policy.charset()
        self.assertTrue(any(c in string.ascii_lowercase for c in charset))
        self.assertTrue(any(c in string.ascii_uppercase for c in charset))
        self.assertTrue(any(c in string.digits for c in charset))

    def test_charset_raises_when_all_disabled(self):
        policy = PasswordPolicy(use_lower=False, use_upper=False, use_digits=False, use_symbols=False)
        with self.assertRaises(ValueError):
            policy.charset()

    def test_avoid_ambiguous_removes_chars(self):
        policy = PasswordPolicy(avoid_ambiguous=True)
        charset = policy.charset()
        for ambiguous_char in "lI1O0":
            self.assertNotIn(ambiguous_char, charset)


class TestGeneratePassword(unittest.TestCase):
    def test_correct_length(self):
        policy = PasswordPolicy(length=24)
        self.assertEqual(len(generate_password(policy)), 24)

    def test_minimum_length_enforced(self):
        with self.assertRaises(ValueError):
            generate_password(PasswordPolicy(length=2))

    def test_contains_all_active_groups_when_min_of_each(self):
        policy = PasswordPolicy(length=16, min_of_each=True)
        pwd = generate_password(policy)
        self.assertTrue(any(c in string.ascii_lowercase for c in pwd))
        self.assertTrue(any(c in string.ascii_uppercase for c in pwd))
        self.assertTrue(any(c in string.digits for c in pwd))
        self.assertTrue(any(c in policy.symbols for c in pwd))

    def test_two_generated_passwords_are_different(self):
        policy = PasswordPolicy(length=16)
        self.assertNotEqual(generate_password(policy), generate_password(policy))

    def test_length_too_short_for_required_groups_raises(self):
        with self.assertRaises(ValueError):
            generate_password(PasswordPolicy(length=2, min_of_each=True))

    def test_only_digits_policy(self):
        policy = PasswordPolicy(length=10, use_lower=False, use_upper=False, use_digits=True, use_symbols=False)
        pwd = generate_password(policy)
        self.assertTrue(all(c in string.digits for c in pwd))


class TestPersonalizedPassword(unittest.TestCase):
    def test_length_is_preserved(self):
        policy = PasswordPolicy(length=16)
        pwd = generate_personalized_password(policy, "sara")
        self.assertEqual(len(pwd), 16)

    def test_empty_keyword_falls_back_to_random(self):
        policy = PasswordPolicy(length=12)
        pwd = generate_personalized_password(policy, "   ")
        self.assertEqual(len(pwd), 12)

    def test_long_keyword_gets_truncated_to_length(self):
        policy = PasswordPolicy(length=6)
        pwd = generate_personalized_password(policy, "averylongkeyword")
        self.assertEqual(len(pwd), 6)


class TestGeneratePassphrase(unittest.TestCase):
    def test_word_count(self):
        phrase = generate_passphrase(word_count=6, add_number=False)
        self.assertEqual(len(phrase.split("-")), 6)

    def test_minimum_word_count_enforced(self):
        with self.assertRaises(ValueError):
            generate_passphrase(word_count=2)

    def test_custom_separator(self):
        phrase = generate_passphrase(word_count=4, separator="_", add_number=False)
        self.assertIn("_", phrase)
        self.assertNotIn("-", phrase)

    def test_add_number_appends_digits(self):
        phrase = generate_passphrase(word_count=4, add_number=True)
        self.assertTrue(phrase.split("-")[-1].isdigit())


class TestEstimateStrength(unittest.TestCase):
    def test_empty_password(self):
        report = estimate_strength("")
        self.assertEqual(report.entropy_bits, 0.0)
        self.assertEqual(report.rating, "Empty")

    def test_weak_password_rated_low(self):
        report = estimate_strength("abc")
        self.assertIn(report.rating, ["Very weak", "Weak"])

    def test_strong_password_rated_high(self):
        report = estimate_strength("K7#mP9$xL2@qR5!vN8&wZ4^t")
        self.assertIn(report.rating, ["Strong", "Very strong"])

    def test_entropy_increases_with_length(self):
        short_report = estimate_strength("Ab3$")
        long_report = estimate_strength("Ab3$Ab3$Ab3$Ab3$")
        self.assertGreater(long_report.entropy_bits, short_report.entropy_bits)


if __name__ == "__main__":
    unittest.main()
