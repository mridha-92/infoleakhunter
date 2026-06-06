import pytest

from infoleakhunter.models.finding import Confidence, Finding, Severity
from infoleakhunter.utils.severity import (
    calculate_confidence,
    calculate_severity,
    create_finding,
    get_cwe,
    get_owasp,
    get_recommendation,
)


class TestSeverityEngine:
    def test_calculate_severity_critical(self):
        severity = calculate_severity("secrets")
        assert severity == Severity.CRITICAL

    def test_calculate_severity_high(self):
        severity = calculate_severity("sensitive_file")
        assert severity == Severity.HIGH

    def test_calculate_severity_medium(self):
        severity = calculate_severity("http_header")
        assert severity == Severity.MEDIUM

    def test_calculate_severity_low(self):
        severity = calculate_severity("dns")
        assert severity == Severity.LOW

    def test_calculate_confidence_certain_200(self):
        confidence = calculate_confidence("secrets", "secret=AKIAIOSFODNN7EXAMPLE", 200)
        assert confidence == Confidence.CERTAIN

    def test_calculate_confidence_medium_redirect(self):
        confidence = calculate_confidence("sensitive_file", "content", 301)
        assert confidence == Confidence.MEDIUM

    def test_calculate_confidence_speculative(self):
        confidence = calculate_confidence("unknown", "", None)
        assert confidence == Confidence.SPECULATIVE

    def test_get_cwe(self):
        assert get_cwe("secrets") == "CWE-798"
        assert get_cwe("sensitive_file") == "CWE-530"
        assert get_cwe("unknown") == "CWE-200"

    def test_get_owasp(self):
        assert get_owasp("secrets") == "OWASP:API8"
        assert get_owasp("http_header") == "OWASP:API4"

    def test_get_recommendation(self):
        rec = get_recommendation("secrets")
        assert len(rec) > 0
        assert "revoke" in rec.lower()

    def test_create_finding(self):
        finding = create_finding(
            target="https://example.com",
            module="secrets",
            title="AWS Key Found",
            evidence="AKIAIOSFODNN7EXAMPLE",
            url="https://example.com/.env",
            status_code=200,
        )
        assert finding.target == "https://example.com"
        assert finding.module == "secrets"
        assert finding.severity == Severity.CRITICAL
        assert finding.confidence == Confidence.CERTAIN
        assert finding.cwe == "CWE-798"
        assert len(finding.recommendation) > 0
        assert finding.cvss_estimate.startswith("CVSS:")
