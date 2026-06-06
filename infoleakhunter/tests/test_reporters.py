import json
import os
import tempfile

import pytest

from infoleakhunter.models.finding import Confidence, Finding, FindingCollection, Severity
from infoleakhunter.reporter.csv_reporter import CSVReporter
from infoleakhunter.reporter.json_reporter import JSONReporter
from infoleakhunter.reporter.markdown_reporter import MarkdownReporter


@pytest.fixture
def sample_findings():
    collection = FindingCollection()
    collection.add(Finding(
        target="https://example.com",
        module="secrets",
        title="AWS Key Found",
        severity=Severity.CRITICAL,
        confidence=Confidence.CERTAIN,
        evidence="AKIAIOSFODNN7EXAMPLE",
        cwe="CWE-798",
        owasp="OWASP:API8",
        recommendation="Revoke and rotate the key",
        url="https://example.com/.env",
    ))
    collection.add(Finding(
        target="https://example.com",
        module="http_header",
        title="Server header exposes nginx version",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        evidence="Server: nginx/1.18.0",
        cwe="CWE-200",
        owasp="OWASP:API4",
        recommendation="Hide server version",
    ))
    return collection


@pytest.fixture
def scan_stats():
    return {
        "target": "https://example.com",
        "total_urls": 1,
        "completed_urls": 1,
        "failed_urls": 0,
        "total_findings": 2,
        "duration_seconds": 10.5,
        "findings": {"Critical": 1, "High": 0, "Medium": 1, "Low": 0, "Informational": 0},
    }


class TestJSONReporter:
    def test_json_output(self, sample_findings, scan_stats):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            tmp_path = f.name

        try:
            reporter = JSONReporter(tmp_path)
            result = reporter.generate(sample_findings, scan_stats)

            data = json.loads(result)
            assert data["tool"]["name"] == "InfoLeakHunter"
            assert data["scan_summary"]["total_findings"] == 2
            assert len(data["findings"]) == 2
            assert data["findings"][0]["module"] == "secrets"
            assert data["findings"][0]["severity"] == "Critical"

            with open(tmp_path) as f:
                file_data = json.load(f)
            assert file_data["scan_summary"]["total_findings"] == 2

        finally:
            os.unlink(tmp_path)


class TestCSVReporter:
    def test_csv_output(self, sample_findings, scan_stats):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            tmp_path = f.name

        try:
            reporter = CSVReporter(tmp_path)
            result = reporter.generate(sample_findings, scan_stats)

            lines = result.strip().split("\n")
            assert len(lines) == 3  # header + 2 findings
            assert "Target" in lines[0]
            assert "Critical" in result

            with open(tmp_path) as f:
                content = f.read()
            assert "Target" in content

        finally:
            os.unlink(tmp_path)


class TestMarkdownReporter:
    def test_markdown_output(self, sample_findings, scan_stats):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
            tmp_path = f.name

        try:
            reporter = MarkdownReporter(tmp_path)
            result = reporter.generate(sample_findings, scan_stats)

            assert "# InfoLeakHunter Scan Report" in result
            assert "Critical" in result
            assert "AWS Key Found" in result

            with open(tmp_path) as f:
                content = f.read()
            assert "# InfoLeakHunter Scan Report" in content

        finally:
            os.unlink(tmp_path)
