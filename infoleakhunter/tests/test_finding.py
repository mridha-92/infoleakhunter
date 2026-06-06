import pytest

from infoleakhunter.models.finding import Confidence, Finding, FindingCollection, Severity


class TestFindingModel:
    def test_finding_creation(self):
        finding = Finding(
            target="https://example.com",
            module="test",
            title="Test Finding",
            severity=Severity.HIGH,
            confidence=Confidence.CERTAIN,
            evidence="evidence text",
            cwe="CWE-200",
            owasp="OWASP:API8",
            recommendation="Fix it",
        )
        assert finding.target == "https://example.com"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.CERTAIN

    def test_finding_to_dict(self):
        finding = Finding(
            target="https://example.com",
            module="test",
            title="Test",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence="test evidence",
        )
        d = finding.to_dict()
        assert d["target"] == "https://example.com"
        assert d["severity"] == "Medium"
        assert d["confidence"] == "High"

    def test_finding_from_dict(self):
        data = {
            "target": "https://example.com",
            "module": "test",
            "title": "Test",
            "severity": "High",
            "confidence": "Certain",
            "evidence": "test",
            "cwe": "CWE-200",
            "owasp": "OWASP:API8",
            "recommendation": "Fix",
            "url": "https://example.com/test",
            "parameter": "",
            "description": "",
            "cvss_estimate": "",
            "timestamp": "",
            "tags": [],
        }
        finding = Finding.from_dict(data)
        assert finding.target == "https://example.com"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.CERTAIN

    def test_finding_fingerprint(self):
        f1 = Finding("https://a.com", "test", "Title", Severity.HIGH, Confidence.CERTAIN, "evidence")
        f2 = Finding("https://a.com", "test", "Title", Severity.HIGH, Confidence.CERTAIN, "different evidence")
        assert f1.fingerprint_hash() == f2.fingerprint_hash()

        f3 = Finding("https://b.com", "test", "Title", Severity.HIGH, Confidence.CERTAIN, "evidence")
        assert f1.fingerprint_hash() != f3.fingerprint_hash()


class TestFindingCollection:
    def test_add_and_count(self):
        collection = FindingCollection()
        f1 = Finding("https://a.com", "test", "T1", Severity.HIGH, Confidence.CERTAIN, "e1")
        f2 = Finding("https://a.com", "test", "T2", Severity.MEDIUM, Confidence.HIGH, "e2")

        assert collection.add(f1) is True
        assert collection.add(f2) is True
        assert collection.total() == 2

    def test_deduplication(self):
        collection = FindingCollection()
        f1 = Finding("https://a.com", "test", "T1", Severity.HIGH, Confidence.CERTAIN, "e1")
        f2 = Finding("https://a.com", "test", "T1", Severity.HIGH, Confidence.CERTAIN, "e2")

        assert collection.add(f1) is True
        assert collection.add(f2) is False
        assert collection.total() == 1

    def test_by_severity(self):
        collection = FindingCollection()
        collection.add(Finding("https://a.com", "t", "T1", Severity.CRITICAL, Confidence.CERTAIN, "e"))
        collection.add(Finding("https://a.com", "t", "T2", Severity.HIGH, Confidence.CERTAIN, "e"))
        collection.add(Finding("https://a.com", "t", "T3", Severity.MEDIUM, Confidence.CERTAIN, "e"))

        assert len(collection.by_severity(Severity.CRITICAL)) == 1
        assert len(collection.by_severity(Severity.HIGH)) == 1
        assert len(collection.by_severity(Severity.MEDIUM)) == 1

    def test_by_module(self):
        collection = FindingCollection()
        collection.add(Finding("https://a.com", "secrets", "T1", Severity.CRITICAL, Confidence.CERTAIN, "e"))
        collection.add(Finding("https://a.com", "http_header", "T2", Severity.MEDIUM, Confidence.HIGH, "e"))

        assert len(collection.by_module("secrets")) == 1
        assert len(collection.by_module("http_header")) == 1

    def test_severity_counts(self):
        collection = FindingCollection()
        collection.add(Finding("https://a.com", "t", "T1", Severity.CRITICAL, Confidence.CERTAIN, "e"))
        collection.add(Finding("https://a.com", "t", "T2", Severity.CRITICAL, Confidence.CERTAIN, "e"))
        collection.add(Finding("https://a.com", "t", "T3", Severity.HIGH, Confidence.CERTAIN, "e"))

        counts = collection.severity_counts()
        assert counts["Critical"] == 2
        assert counts["High"] == 1
        assert counts["Medium"] == 0

    def test_to_dict_list(self):
        collection = FindingCollection()
        collection.add(Finding("https://a.com", "t", "T1", Severity.HIGH, Confidence.CERTAIN, "e"))
        dict_list = collection.to_dict_list()
        assert len(dict_list) == 1
        assert dict_list[0]["title"] == "T1"

    def test_clear(self):
        collection = FindingCollection()
        collection.add(Finding("https://a.com", "t", "T1", Severity.HIGH, Confidence.CERTAIN, "e"))
        assert collection.total() == 1
        collection.clear()
        assert collection.total() == 0

    def test_add_all(self):
        collection = FindingCollection()
        findings = [
            Finding("https://a.com", "t", "T1", Severity.HIGH, Confidence.CERTAIN, "e"),
            Finding("https://a.com", "t", "T2", Severity.MEDIUM, Confidence.HIGH, "e"),
            Finding("https://a.com", "t", "T1", Severity.HIGH, Confidence.CERTAIN, "e"),
        ]
        count = collection.add_all(findings)
        assert count == 2
        assert collection.total() == 2


class TestSeverityOrdering:
    def test_severity_ordering(self):
        assert Severity.CRITICAL > Severity.HIGH
        assert Severity.HIGH > Severity.MEDIUM
        assert Severity.MEDIUM > Severity.LOW
        assert Severity.LOW > Severity.INFO
        assert Severity.CRITICAL >= Severity.CRITICAL
        assert Severity.INFO <= Severity.INFO
