from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime, timezone
from typing import Any

from infoleakhunter.config import load_config
from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.reporter import (
    ConsoleReporter,
    CSVReporter,
    HTMLReporter,
    JSONReporter,
    MarkdownReporter,
)
from infoleakhunter.scanner import (
    APIDocsScanner,
    CloudExposureScanner,
    DNSLeakageScanner,
    DirectoryListingScanner,
    ErrorDisclosureScanner,
    GitExposureScanner,
    HTTPHeaderScanner,
    JavaScriptScanner,
    MetadataScanner,
    SecretScanner,
    SensitiveFileScanner,
    SourceCodeScanner,
)
from infoleakhunter.utils.fingerprints import TechFingerprinter
from infoleakhunter.utils.http_client import HTTPClient
from infoleakhunter.utils.progress import ProgressDisplay

logger = logging.getLogger("infoleakhunter.engine")


class ScanEngine:
    def __init__(self, targets: list[str], config: dict[str, Any] | None = None, options: dict[str, Any] | None = None) -> None:
        self.targets = [t.rstrip("/") for t in targets]
        self.config = config or load_config()
        self.options = options or {}
        self.findings = FindingCollection()
        self.scan_stats: dict[str, Any] = {
            "target": targets[0] if targets else "",
            "total_urls": len(targets),
            "completed_urls": 0,
            "failed_urls": 0,
            "findings": {},
            "total_findings": 0,
            "duration_seconds": 0,
            "start_time": "",
            "end_time": "",
        }
        self._progress = ProgressDisplay()
        self._shutdown = False

    def _setup_signal_handlers(self) -> None:
        if sys.platform != "win32":
            try:
                loop = asyncio.get_event_loop()
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(sig, self._handle_shutdown)
            except NotImplementedError:
                pass

    def _handle_shutdown(self) -> None:
        self._shutdown = True
        logger.info("Shutdown requested...")

    async def run(self) -> FindingCollection:
        self.scan_stats["start_time"] = datetime.now(timezone.utc).isoformat()
        self._progress.start(len(self.targets))

        self.config["scan"]["concurrent_requests"] = self.options.get("threads", self.config["scan"].get("concurrent_requests", 100))

        async with HTTPClient(self.config) as http_client:
            sem = asyncio.Semaphore(self.options.get("threads", self.config["scan"].get("concurrent_requests", 100)))
            batch_size = self.config["scan"].get("batch_size", 100)

            for batch_start in range(0, len(self.targets), batch_size):
                if self._shutdown:
                    break

                batch = self.targets[batch_start:batch_start + batch_size]
                tasks = []
                for target in batch:
                    tasks.append(self._scan_target(target, http_client, sem))

                results = await asyncio.gather(*tasks, return_exceptions=True)

                for result in results:
                    if isinstance(result, Exception):
                        logger.error(f"Scan task failed: {result}")
                        self._progress.update(failed=1)
                    elif isinstance(result, tuple):
                        target_findings, tech_info = result
                        new_count = self.findings.add_all(target_findings)
                        if new_count > 0:
                            sev_counts = {}
                            for f in target_findings:
                                sev = f.severity.value
                                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                            self._progress.update(findings=sev_counts)
                        self._progress.update(completed=1)

        self.scan_stats["end_time"] = datetime.now(timezone.utc).isoformat()
        summary = self._progress.stop()
        self.scan_stats["completed_urls"] = summary.get("completed_urls", 0)
        self.scan_stats["failed_urls"] = summary.get("failed_urls", 0)
        self.scan_stats["findings"] = summary.get("findings", {})
        self.scan_stats["total_findings"] = summary.get("total_findings", 0)
        self.scan_stats["duration_seconds"] = summary.get("duration_seconds", 0)

        self._generate_reports()

        return self.findings

    async def _scan_target(
        self,
        target: str,
        http_client: HTTPClient,
        sem: asyncio.Semaphore,
    ) -> tuple[list[Any], dict]:
        async with sem:
            try:
                scanners = self._create_scanners(target, http_client)
                all_findings: list[Any] = []

                for scanner in scanners:
                    try:
                        result = await scanner.scan()
                        all_findings.extend(result.all())
                    except Exception as e:
                        logger.debug(f"Scanner {type(scanner).__name__} failed for {target}: {e}")

                fp = TechFingerprinter()
                try:
                    status, headers, body, cookies = await http_client.check_url(target)
                    if headers:
                        fp.fingerprint(headers, body, cookies)
                except Exception:
                    pass

                return all_findings, fp.detected

            except Exception as e:
                logger.error(f"Failed to scan {target}: {e}")
                raise

    def _create_scanners(self, target: str, http_client: HTTPClient) -> list:
        return [
            SensitiveFileScanner(target, http_client, self.config),
            HTTPHeaderScanner(target, http_client, self.config),
            SourceCodeScanner(target, http_client, self.config),
            JavaScriptScanner(target, http_client, self.config),
            SecretScanner(target, http_client, self.config),
            ErrorDisclosureScanner(target, http_client, self.config),
            DirectoryListingScanner(target, http_client, self.config),
            APIDocsScanner(target, http_client, self.config),
            GitExposureScanner(target, http_client, self.config),
            CloudExposureScanner(target, http_client, self.config),
            MetadataScanner(target, http_client, self.config),
            DNSLeakageScanner(target, http_client, self.config),
        ]

    def _generate_reports(self) -> None:
        report_options = {
            "json": self.options.get("json", False),
            "json_file": self.options.get("json_file", ""),
            "csv": self.options.get("csv", False),
            "csv_file": self.options.get("csv_file", ""),
            "html": self.options.get("html", False),
            "html_file": self.options.get("html_file", ""),
            "markdown": self.options.get("markdown", False),
            "markdown_file": self.options.get("markdown_file", ""),
            "console": self.options.get("console", True),
        }

        if report_options.get("json") and report_options.get("json_file"):
            reporter = JSONReporter(report_options["json_file"])
            reporter.generate(self.findings, self.scan_stats)

        if report_options.get("csv") and report_options.get("csv_file"):
            reporter = CSVReporter(report_options["csv_file"])
            reporter.generate(self.findings, self.scan_stats)

        if report_options.get("html") and report_options.get("html_file"):
            reporter = HTMLReporter(report_options["html_file"])
            reporter.generate(self.findings, self.scan_stats)

        if report_options.get("markdown") and report_options.get("markdown_file"):
            reporter = MarkdownReporter(report_options["markdown_file"])
            reporter.generate(self.findings, self.scan_stats)

        if report_options.get("console", True):
            reporter = ConsoleReporter()
            reporter.generate(self.findings, self.scan_stats)


def run_scan(targets: list[str], options: dict[str, Any] | None = None) -> FindingCollection:
    options = options or {}
    config = load_config(options.get("config"))

    engine = ScanEngine(targets, config, options)

    if sys.platform != "win32":
        try:
            import uvloop
            uvloop.install()
        except ImportError:
            pass

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        findings = loop.run_until_complete(engine.run())
        return findings
    finally:
        try:
            loop.close()
        except Exception:
            pass
