from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self) < order.index(other)

    def __le__(self, other: Severity) -> bool:
        return self == other or self < other

    def __gt__(self, other: Severity) -> bool:
        return not self <= other

    def __ge__(self, other: Severity) -> bool:
        return not self < other


class Confidence(Enum):
    CERTAIN = "Certain"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    SPECULATIVE = "Speculative"

    def score(self) -> float:
        mapping = {
            Confidence.CERTAIN: 1.0,
            Confidence.HIGH: 0.8,
            Confidence.MEDIUM: 0.5,
            Confidence.LOW: 0.3,
            Confidence.SPECULATIVE: 0.1,
        }
        return mapping[self]


@dataclass
class Finding:
    target: str
    module: str
    title: str
    severity: Severity
    confidence: Confidence
    evidence: str
    cwe: str = ""
    owasp: str = ""
    recommendation: str = ""
    url: str = ""
    parameter: str = ""
    description: str = ""
    cvss_estimate: str = ""
    fingerprint: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tags: list[str] = field(default_factory=list)

    def fingerprint_hash(self) -> str:
        raw = f"{self.target}|{self.module}|{self.title}|{self.severity.value}"
        return hashlib.sha256(raw.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "module": self.module,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence": self.evidence[:1000] if self.evidence else "",
            "cwe": self.cwe,
            "owasp": self.owasp,
            "recommendation": self.recommendation,
            "url": self.url,
            "parameter": self.parameter,
            "description": self.description,
            "cvss_estimate": self.cvss_estimate,
            "timestamp": self.timestamp,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            target=data.get("target", ""),
            module=data.get("module", ""),
            title=data.get("title", ""),
            severity=Severity(data.get("severity", "Informational")),
            confidence=Confidence(data.get("confidence", "Medium")),
            evidence=data.get("evidence", ""),
            cwe=data.get("cwe", ""),
            owasp=data.get("owasp", ""),
            recommendation=data.get("recommendation", ""),
            url=data.get("url", ""),
            parameter=data.get("parameter", ""),
            description=data.get("description", ""),
            cvss_estimate=data.get("cvss_estimate", ""),
            timestamp=data.get("timestamp", ""),
            tags=data.get("tags", []),
        )


class FindingCollection:
    def __init__(self) -> None:
        self._findings: list[Finding] = []
        self._fingerprints: set[str] = set()

    def add(self, finding: Finding) -> bool:
        fp = finding.fingerprint_hash()
        if fp in self._fingerprints:
            return False
        self._fingerprints.add(fp)
        self._findings.append(finding)
        return True

    def add_all(self, findings: list[Finding]) -> int:
        count = 0
        for f in findings:
            if self.add(f):
                count += 1
        return count

    def all(self) -> list[Finding]:
        return sorted(self._findings, key=lambda x: x.severity)

    def by_severity(self, severity: Severity) -> list[Finding]:
        return [f for f in self._findings if f.severity == severity]

    def by_module(self, module: str) -> list[Finding]:
        return [f for f in self._findings if f.module == module]

    def by_confidence(self, confidence: Confidence) -> list[Finding]:
        return [f for f in self._findings if f.confidence == confidence]

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for s in Severity:
            counts[s.value] = 0
        for f in self._findings:
            counts[f.severity.value] += 1
        return counts

    def total(self) -> int:
        return len(self._findings)

    def clear(self) -> None:
        self._findings.clear()
        self._fingerprints.clear()

    def to_dict_list(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self._findings]
