from __future__ import annotations

import logging
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from infoleakhunter.models.finding import FindingCollection, Severity

logger = logging.getLogger("infoleakhunter.reporter.console")


class ConsoleReporter:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def generate(self, findings: FindingCollection, scan_stats: dict[str, Any]) -> None:
        self._print_header(scan_stats)
        self._print_summary_table(scan_stats)
        self._print_findings(findings, scan_stats)
        self._print_footer(scan_stats)

    def _print_header(self, stats: dict[str, Any]) -> None:
        self.console.print()
        self.console.print(Panel(
            "[bold cyan]InfoLeakHunter[/bold cyan] - Information Disclosure Vulnerability Scanner\n"
            "[dim]Version 1.0.0[/dim]",
            border_style="cyan",
        ))
        self.console.print()

    def _print_summary_table(self, stats: dict[str, Any]) -> None:
        sev_counts = stats.get("findings", {})

        table = Table(title="Scan Summary", show_header=True, header_style="bold")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Target", stats.get("target", "Unknown"))
        table.add_row("URLs Scanned", f"{stats.get('completed_urls', 0)}/{stats.get('total_urls', 0)}")
        table.add_row("Failed URLs", str(stats.get("failed_urls", 0)))
        table.add_row("Duration", f"{stats.get('duration_seconds', 0):.1f}s")
        table.add_row("Total Findings", str(stats.get("total_findings", 0)))

        self.console.print(table)
        self.console.print()

        severity_table = Table(title="Findings by Severity", show_header=True, header_style="bold")
        severity_table.add_column("Severity", style="cyan")
        severity_table.add_column("Count", style="white")

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = sev_counts.get(sev.value, 0)
            style = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "green",
            }.get(sev, "white")
            severity_table.add_row(sev.value, Text(str(count), style=style))

        self.console.print(severity_table)
        self.console.print()

    def _print_findings(self, findings: FindingCollection, stats: dict[str, Any]) -> None:
        all_findings = findings.all()

        if not all_findings:
            self.console.print("[bold green]No findings discovered![/bold green]")
            self.console.print()
            return

        self.console.print("[bold]Details:[/bold]")
        self.console.print()

        for i, finding in enumerate(all_findings, 1):
            sev_style = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "green",
            }.get(finding.severity, "white")

            self.console.print(f"[{sev_style}]#{i} {finding.severity.value}[/{sev_style}] {finding.title}")
            self.console.print(f"      [dim]Target:[/dim] {finding.target}")
            self.console.print(f"      [dim]Module:[/dim] {finding.module}")
            if finding.url:
                self.console.print(f"      [dim]URL:[/dim] {finding.url}")
            self.console.print(f"      [dim]Confidence:[/dim] {finding.confidence.value}")
            self.console.print(f"      [dim]CWE:[/dim] {finding.cwe} | [dim]OWASP:[/dim] {finding.owasp}")
            if finding.evidence:
                evidence = finding.evidence[:300]
                self.console.print(f"      [dim]Evidence:[/dim] {evidence}")
            self.console.print()

    def _print_footer(self, stats: dict[str, Any]) -> None:
        self.console.print("[bold cyan]Scan Complete[/bold cyan]")
        self.console.print(f"Scanned {stats.get('completed_urls', 0)} URLs in {stats.get('duration_seconds', 0):.1f}s")
        self.console.print(f"Found {stats.get('total_findings', 0)} potential information disclosures")
        self.console.print()
