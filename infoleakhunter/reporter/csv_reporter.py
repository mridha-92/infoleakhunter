from __future__ import annotations

import csv
import logging
from typing import Any

from infoleakhunter.models.finding import FindingCollection

logger = logging.getLogger("infoleakhunter.reporter.csv")

CSV_HEADERS = [
    "Target", "Module", "Title", "Severity", "Confidence", "CWE", "OWASP",
    "URL", "Description", "Recommendation", "CVSS", "Evidence", "Tags",
]


class CSVReporter:
    def __init__(self, output_path: str) -> None:
        self.output_path = output_path

    def generate(self, findings: FindingCollection, scan_stats: dict[str, Any]) -> str:
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(CSV_HEADERS)

        for finding in findings.all():
            writer.writerow([
                finding.target,
                finding.module,
                finding.title,
                finding.severity.value,
                finding.confidence.value,
                finding.cwe,
                finding.owasp,
                finding.url,
                finding.description,
                finding.recommendation,
                finding.cvss_estimate,
                finding.evidence[:500],
                "; ".join(finding.tags),
            ])

        csv_str = output.getvalue()
        output.close()

        if self.output_path:
            try:
                with open(self.output_path, "w", newline="") as f:
                    f.write(csv_str)
                logger.info(f"CSV report written to {self.output_path}")
            except Exception as e:
                logger.error(f"Failed to write CSV report: {e}")

        return csv_str
