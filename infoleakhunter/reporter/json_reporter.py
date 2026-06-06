from __future__ import annotations

import json
import logging
from typing import Any

from infoleakhunter.models.finding import FindingCollection

logger = logging.getLogger("infoleakhunter.reporter.json")


class JSONReporter:
    def __init__(self, output_path: str) -> None:
        self.output_path = output_path

    def generate(self, findings: FindingCollection, scan_stats: dict[str, Any]) -> str:
        report = {
            "tool": {
                "name": "InfoLeakHunter",
                "version": "1.0.0",
                "description": "Automated Information Disclosure Vulnerability Scanner",
            },
            "scan_summary": {
                "total_urls": scan_stats.get("total_urls", 0),
                "completed_urls": scan_stats.get("completed_urls", 0),
                "failed_urls": scan_stats.get("failed_urls", 0),
                "total_findings": scan_stats.get("total_findings", 0),
                "duration_seconds": scan_stats.get("duration_seconds", 0),
                "severity_counts": scan_stats.get("findings", {}),
            },
            "findings": findings.to_dict_list(),
        }

        json_str = json.dumps(report, indent=2, default=str)

        if self.output_path:
            try:
                with open(self.output_path, "w") as f:
                    f.write(json_str)
                logger.info(f"JSON report written to {self.output_path}")
            except Exception as e:
                logger.error(f"Failed to write JSON report: {e}")

        return json_str
