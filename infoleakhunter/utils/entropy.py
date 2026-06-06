from __future__ import annotations

import math
import re
from collections import Counter


class EntropyCalculator:
    SHANNON_THRESHOLD = 3.5
    BASE64_PATTERN = re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
    HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")

    @staticmethod
    def shannon_entropy(data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for count in Counter(data).values():
            p = count / len(data)
            entropy -= p * math.log2(p) if p > 0 else 0
        return entropy

    @staticmethod
    def is_high_entropy(data: str, threshold: float | None = None) -> bool:
        threshold = threshold or EntropyCalculator.SHANNON_THRESHOLD
        return EntropyCalculator.shannon_entropy(data) >= threshold

    @staticmethod
    def charset_entropy(data: str) -> float:
        if not data:
            return 0.0
        unique_chars = len(set(data))
        return unique_chars / len(data)

    @staticmethod
    def is_likely_secret(data: str) -> tuple[bool, float]:
        entropy = EntropyCalculator.shannon_entropy(data)
        if len(data) < 8:
            return False, entropy
        if entropy >= EntropyCalculator.SHANNON_THRESHOLD:
            return True, entropy
        return False, entropy

    @staticmethod
    def classify_string(data: str) -> str:
        if not data:
            return "empty"
        entropy = EntropyCalculator.shannon_entropy(data)
        if EntropyCalculator.BASE64_PATTERN.match(data) and entropy > 4.0:
            return "high_entropy_base64"
        if EntropyCalculator.HEX_PATTERN.match(data) and len(data) >= 16 and entropy > 3.0:
            return "high_entropy_hex"
        if entropy > 4.5:
            return "high_entropy"
        if entropy > EntropyCalculator.SHANNON_THRESHOLD:
            return "medium_entropy"
        return "low_entropy"
