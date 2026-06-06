from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from infoleakhunter.models.finding import FindingCollection, Severity

logger = logging.getLogger("infoleakhunter.reporter.html")

REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>InfoLeakHunter Report - {target}</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: #0f1117; color: #e1e4e8; line-height: 1.6; }}
.container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
.header {{ background: linear-gradient(135deg, #1a1d24 0%, #2d333b 100%); padding: 30px; border-radius: 8px; margin-bottom: 24px; border: 1px solid #30363d; }}
.header h1 {{ color: #58a6ff; font-size: 28px; margin-bottom: 8px; }}
.header .meta {{ color: #8b949e; font-size: 14px; }}
.summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.stat-card {{ background: #161b22; padding: 20px; border-radius: 8px; border: 1px solid #30363d; text-align: center; }}
.stat-card .value {{ font-size: 32px; font-weight: bold; }}
.stat-card .label {{ color: #8b949e; font-size: 12px; text-transform: uppercase; margin-top: 4px; }}
.critical .value {{ color: #f85149; }} .high .value {{ color: #d29922; }} .medium .value {{ color: #d29922; }} .low .value {{ color: #58a6ff; }} .info .value {{ color: #3fb950; }}
.severity-bar {{ display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 16px 0; }}
.severity-bar div {{ height: 100%; transition: width 0.3s; }}
.sev-critical {{ background: #f85149; }} .sev-high {{ background: #d29922; }} .sev-medium {{ background: #9e6a03; }} .sev-low {{ background: #58a6ff; }} .sev-info {{ background: #3fb950; }}
.finding {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; margin-bottom: 16px; padding: 20px; }}
.finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
.finding-title {{ font-size: 16px; font-weight: 600; color: #f0f6fc; }}
.severity-badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
.sev-Critical {{ background: #f85149; color: #fff; }} .sev-High {{ background: #d29922; color: #000; }} .sev-Medium {{ background: #9e6a03; color: #fff; }} .sev-Low {{ background: #58a6ff; color: #000; }} .sev-Informational {{ background: #3fb950; color: #000; }}
.finding-meta {{ display: flex; gap: 16px; margin-bottom: 12px; flex-wrap: wrap; }}
.finding-meta span {{ font-size: 12px; color: #8b949e; }}
.finding-meta strong {{ color: #e1e4e8; }}
.finding-evidence {{ background: #0d1117; padding: 12px; border-radius: 4px; margin-top: 8px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; color: #7ee787; }}
.finding-recommendation {{ margin-top: 12px; padding: 12px; background: #1a1d24; border-left: 3px solid #58a6ff; border-radius: 4px; font-size: 13px; color: #c9d1d9; }}
.finding-tags {{ display: flex; gap: 4px; flex-wrap: wrap; margin-top: 8px; }}
.tag {{ display: inline-block; padding: 2px 6px; background: #21262d; border: 1px solid #30363d; border-radius: 4px; font-size: 10px; color: #8b949e; }}
.no-findings {{ text-align: center; padding: 60px 20px; color: #8b949e; }}
.no-findings h2 {{ color: #3fb950; margin-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #30363d; }}
th {{ color: #8b949e; font-size: 12px; text-transform: uppercase; }}
td {{ font-size: 14px; }}
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>InfoLeakHunter Scan Report</h1>
<div class="meta">
Generated: {generated_at} | Target: {target} | Duration: {duration:.1f}s
</div>
</div>
<h2>Executive Summary</h2>
<div class="summary">
<div class="stat-card"><div class="value">{total_urls}</div><div class="label">URLs Scanned</div></div>
<div class="stat-card"><div class="value">{total_findings}</div><div class="label">Total Findings</div></div>
<div class="stat-card {sev_critical_class}"><div class="value">{critical_count}</div><div class="label">Critical</div></div>
<div class="stat-card {sev_high_class}"><div class="value">{high_count}</div><div class="label">High</div></div>
<div class="stat-card {sev_medium_class}"><div class="value">{medium_count}</div><div class="label">Medium</div></div>
<div class="stat-card {sev_low_class}"><div class="value">{low_count}</div><div class="label">Low</div></div>
</div>
<div class="severity-bar">
{severity_bar}
</div>
<h2>Detailed Findings</h2>
{findings_html}
</div>
</body>
</html>
"""


class HTMLReporter:
    def __init__(self, output_path: str) -> None:
        self.output_path = output_path

    def generate(self, findings: FindingCollection, scan_stats: dict[str, Any]) -> str:
        sev_counts = scan_stats.get("findings", {})
        total = sum(sev_counts.values()) if sev_counts else 0

        def esc(text: str) -> str:
            return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

        findings_html = ""
        all_findings = findings.all()

        if not all_findings:
            findings_html = '<div class="no-findings"><h2>No findings discovered</h2><p>The target passed all security checks.</p></div>'
        else:
            for finding in all_findings:
                evidence_html = ""
                if finding.evidence:
                    evidence_html = f'<div class="finding-evidence">{esc(finding.evidence[:1500])}</div>'

                tags_html = ""
                if finding.tags:
                    tags_html = '<div class="finding-tags">' + "".join(
                        f'<span class="tag">{esc(t)}</span>' for t in finding.tags[:10]
                    ) + "</div>"

                findings_html += f"""
                <div class="finding">
                    <div class="finding-header">
                        <div class="finding-title">{esc(finding.title)}</div>
                        <span class="severity-badge sev-{finding.severity.value}">{finding.severity.value}</span>
                    </div>
                    <div class="finding-meta">
                        <span><strong>Target:</strong> {esc(finding.target)}</span>
                        <span><strong>Module:</strong> {finding.module}</span>
                        <span><strong>Confidence:</strong> {finding.confidence.value}</span>
                        <span><strong>CWE:</strong> {finding.cwe}</span>
                        <span><strong>OWASP:</strong> {finding.owasp}</span>
                    </div>
                    {evidence_html}
                    <div class="finding-recommendation">💡 {esc(finding.recommendation)}</div>
                    {tags_html}
                </div>
                """

        total_pixels = max(total, 1)
        severity_bar_parts = []
        for sev, css_class in [
            (Severity.CRITICAL, "sev-critical"),
            (Severity.HIGH, "sev-high"),
            (Severity.MEDIUM, "sev-medium"),
            (Severity.LOW, "sev-low"),
            (Severity.INFO, "sev-info"),
        ]:
            count = sev_counts.get(sev.value, 0)
            width = (count / total_pixels) * 100
            severity_bar_parts.append(
                f'<div class="{css_class}" style="width: {width:.1f}%;"></div>'
            )

        context = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "target": esc(scan_stats.get("target", "Unknown")),
            "duration": scan_stats.get("duration_seconds", 0),
            "total_urls": scan_stats.get("completed_urls", 0),
            "total_findings": total,
            "critical_count": sev_counts.get("Critical", 0),
            "high_count": sev_counts.get("High", 0),
            "medium_count": sev_counts.get("Medium", 0),
            "low_count": sev_counts.get("Low", 0),
            "sev_critical_class": "critical" if sev_counts.get("Critical", 0) > 0 else "",
            "sev_high_class": "high" if sev_counts.get("High", 0) > 0 else "",
            "sev_medium_class": "medium" if sev_counts.get("Medium", 0) > 0 else "",
            "sev_low_class": "low" if sev_counts.get("Low", 0) > 0 else "",
            "severity_bar": "".join(severity_bar_parts),
            "findings_html": findings_html,
        }

        html = REPORT_TEMPLATE.format(**context)

        if self.output_path:
            try:
                with open(self.output_path, "w") as f:
                    f.write(html)
                logger.info(f"HTML report written to {self.output_path}")
            except Exception as e:
                logger.error(f"Failed to write HTML report: {e}")

        return html
