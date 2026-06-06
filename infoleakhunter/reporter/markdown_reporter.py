from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from infoleakhunter.models.finding import FindingCollection, Severity

logger = logging.getLogger("infoleakhunter.reporter.markdown")


class MarkdownReporter:
    def __init__(self, output_path: str) -> None:
        self.output_path = output_path

    def generate(self, findings: FindingCollection, scan_stats: dict[str, Any]) -> str:
        lines: list[str] = []
        lines.append("# InfoLeakHunter Scan Report")
        lines.append("")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        lines.append(f"**Tool:** InfoLeakHunter v1.0.0")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Total URLs Scanned:** {scan_stats.get('completed_urls', 0)}/{scan_stats.get('total_urls', 0)}")
        lines.append(f"- **Failed URLs:** {scan_stats.get('failed_urls', 0)}")
        lines.append(f"- **Total Findings:** {scan_stats.get('total_findings', 0)}")
        lines.append(f"- **Scan Duration:** {scan_stats.get('duration_seconds', 0):.1f}s")
        lines.append("")

        sev_counts = scan_stats.get("findings", {})
        if sev_counts:
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Count |")
            lines.append("|----------|-------|")
            for s in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                count = sev_counts.get(s.value, 0)
                lines.append(f"| {s.value} | {count} |")
            lines.append("")

        lines.append("## Detailed Findings")
        lines.append("")
        lines.append("---")
        lines.append("")

        all_findings = findings.all()
        if not all_findings:
            lines.append("*No findings discovered.*")
            lines.append("")

        for i, finding in enumerate(all_findings, 1):
            severity_icon = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "⚪",
            }.get(finding.severity, "⚪")

            lines.append(f"### {i}. {severity_icon} {finding.title}")
            lines.append("")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Target** | `{finding.target}` |")
            lines.append(f"| **Module** | {finding.module} |")
            lines.append(f"| **Severity** | **{finding.severity.value}** |")
            lines.append(f"| **Confidence** | {finding.confidence.value} |")
            lines.append(f"| **CWE** | {finding.cwe} |")
            lines.append(f"| **OWASP** | {finding.owasp} |")
            if finding.url:
                lines.append(f"| **URL** | `{finding.url}` |")
            if finding.cvss_estimate:
                lines.append(f"| **CVSS** | `{finding.cvss_estimate}` |")
            if finding.description:
                lines.append(f"| **Description** | {finding.description} |")
            if finding.recommendation:
                lines.append(f"| **Recommendation** | {finding.recommendation} |")
            if finding.evidence:
                lines.append(f"| **Evidence** | |")
                lines.append("")
                lines.append("```")
                lines.append(finding.evidence[:800])
                lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")

        md_str = "\n".join(lines)

        if self.output_path:
            try:
                with open(self.output_path, "w") as f:
                    f.write(md_str)
                logger.info(f"Markdown report written to {self.output_path}")
            except Exception as e:
                logger.error(f"Failed to write Markdown report: {e}")

        return md_str
