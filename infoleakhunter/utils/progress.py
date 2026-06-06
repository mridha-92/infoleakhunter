from __future__ import annotations

import threading
from datetime import datetime, timedelta
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from infoleakhunter.models.finding import Severity


class ProgressDisplay:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()
        self._lock = threading.Lock()
        self._start_time: datetime | None = None
        self._total_urls: int = 0
        self._completed_urls: int = 0
        self._findings_counts: dict[str, int] = {s.value: 0 for s in Severity}
        self._failed_urls: int = 0
        self._live: Live | None = None
        self._progress: Progress | None = None
        self._task_id: Any = None

    def start(self, total_urls: int) -> None:
        self._start_time = datetime.now()
        self._total_urls = total_urls
        self._completed_urls = 0
        self._failed_urls = 0

        self._progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=self.console,
            transient=False,
        )
        self._task_id = self._progress.add_task(
            "[cyan]Scanning targets...", total=total_urls
        )

        self._live = Live(self._make_layout(), console=self.console, refresh_per_second=4)
        self._live.__enter__()

    def _make_layout(self) -> Panel:
        table = Table.grid(padding=1)
        table.add_column()

        progress_table = Table.grid(padding=1)
        progress_table.add_row(
            Text(f"Targets: {self._completed_urls}/{self._total_urls}", style="bold"),
            Text(f"Failed: {self._failed_urls}", style="bold red"),
        )
        if self._progress:
            progress_table.add_row(self._progress)

        severity_table = Table.grid(padding=(0, 2))
        severity_table.add_column(style="bold")
        severity_table.add_column(style="bold")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            style = {
                Severity.CRITICAL: "bold red",
                Severity.HIGH: "red",
                Severity.MEDIUM: "yellow",
                Severity.LOW: "blue",
                Severity.INFO: "green",
            }[severity]
            severity_table.add_row(
                Text(f"{severity.value}:", style=style),
                Text(str(self._findings_counts[severity.value]), style=style),
            )

        total_findings = sum(self._findings_counts.values())
        severity_table.add_row(
            Text("Total:", style="bold"),
            Text(str(total_findings), style="bold"),
        )

        duration = datetime.now() - self._start_time if self._start_time else timedelta(0)
        info_panel = Panel(
            f"[bold]InfoLeakHunter[/bold] - [cyan]{str(duration).split('.')[0]}[/cyan]",
            border_style="cyan",
        )

        layout = Table.grid(padding=1)
        layout.add_column()
        layout.add_row(info_panel)
        layout.add_row(progress_table)
        layout.add_row(Panel(severity_table, title="Findings", border_style="yellow"))
        return Panel(layout, title="Scan Status", border_style="green")

    def update(self, completed: int | None = None, failed: int | None = None, findings: dict[str, int] | None = None) -> None:
        with self._lock:
            if completed is not None:
                self._completed_urls += completed
                if self._progress and self._task_id is not None:
                    self._progress.update(self._task_id, advance=completed)
            if failed is not None:
                self._failed_urls += failed
            if findings:
                for sev, count in findings.items():
                    if sev in self._findings_counts:
                        self._findings_counts[sev] += count

        if self._live:
            self._live.update(self._make_layout())

    def stop(self) -> dict[str, Any]:
        if self._live:
            self._live.__exit__(None, None, None)
        return self.summary()

    def summary(self) -> dict[str, Any]:
        duration = datetime.now() - self._start_time if self._start_time else timedelta(0)
        return {
            "total_urls": self._total_urls,
            "completed_urls": self._completed_urls,
            "failed_urls": self._failed_urls,
            "findings": dict(self._findings_counts),
            "total_findings": sum(self._findings_counts.values()),
            "duration_seconds": duration.total_seconds(),
        }
