import pytest

from infoleakhunter.utils.entropy import EntropyCalculator


class TestEntropyCalculator:
    def test_shannon_entropy_high(self):
        entropy = EntropyCalculator.shannon_entropy("aB3dE5fG7iJ9kL1mN0oP2qR4sT6uV8wXyZ")
        assert entropy > 4.0

    def test_shannon_entropy_low(self):
        entropy = EntropyCalculator.shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        assert entropy < 1.0

    def test_shannon_entropy_empty(self):
        assert EntropyCalculator.shannon_entropy("") == 0.0

    def test_is_high_entropy_true(self):
        assert EntropyCalculator.is_high_entropy("aB3dE5fG7iJ9kL1mN0oP2qR4sT6uV8wXyZ") is True

    def test_is_high_entropy_false(self):
        assert EntropyCalculator.is_high_entropy("aaaaaa") is False

    def test_is_likely_secret_high_entropy(self):
        is_secret, entropy = EntropyCalculator.is_likely_secret("AKIAIOSFODNN7EXAMPLE12345678")
        assert is_secret is True
        assert entropy > 3.5

    def test_is_likely_secret_short(self):
        is_secret, entropy = EntropyCalculator.is_likely_secret("short")
        assert is_secret is False

    def test_classify_high_entropy_base64(self):
        result = EntropyCalculator.classify_string("dGhpcyBpcyBhIHRlc3Qgc3RyaW5nIGZvciBiYXNlNjQ=")
        assert result == "high_entropy_base64"

    def test_classify_empty(self):
        assert EntropyCalculator.classify_string("") == "empty"

    def test_classify_low_entropy(self):
        assert EntropyCalculator.classify_string("hello") == "low_entropy"

    def test_hex_entropy_high(self):
        result = EntropyCalculator.classify_string("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
        assert result == "high_entropy_hex"

    def test_charset_entropy(self):
        entropy = EntropyCalculator.charset_entropy("abc123!@#")
        assert 0.0 < entropy <= 1.0
