from __future__ import annotations

import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.directory_listing")

DIRECTORY_INDICATORS = [
    ("Index of /", "Apache/Nginx directory listing"),
    ("[PARENTDIR]", "Parent directory link"),
    ("<title>Index of", "Generic directory listing"),
    ("<title>Directory listing for", "Generic directory listing"),
    ("Directory Listing", "Generic directory listing"),
    ("<A HREF=\"?C=N;O=D\">", "Apache directory listing sort control"),
    ("<a href=\"?C=N;O=D\">", "Apache directory listing sort control"),
    ("Last modified</a>", "Directory listing details"),
    ("Parent Directory</a>", "Parent directory navigation"),
]

COMMON_DIRECTORIES = [
    "backup", "backups", "admin", "administrator", "uploads", "files",
    "images", "img", "css", "js", "assets", "static", "public",
    "download", "downloads", "docs", "documentation", "logs", "log",
    "temp", "tmp", "cache", "data", "private", "restricted",
    "api", "v1", "v2", "v3", "graphql", "swagger", "redoc",
    ".git", ".svn", ".hg", ".idea", ".vscode",
    "node_modules", "vendor", "bower_components",
    "wp-content", "wp-includes", "wp-admin",
    "src", "dist", "build", "config", "configuration",
    "test", "tests", "testing", "dev", "development",
    "stage", "staging", "qa", "uat",
    "phpmyadmin", "phpPgAdmin", "adminer",
    "server-status", "server-info",
]

DIRECTORY_EXTENSIONS = [
    "", "/", "/?dir",
]


class DirectoryListingScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        try:
            status, headers, body, cookies = await self.http_client.check_url(self.target)

            if status == 200 and body:
                self._check_directory_listing(body, self.target)

            for directory in COMMON_DIRECTORIES[:20]:
                dir_url = self.normalize_url(directory) + "/"
                try:
                    dir_status, dir_headers, dir_body, dir_cookies = await self.http_client.check_url(dir_url)
                    if dir_status == 200 and dir_body:
                        self._check_directory_listing(dir_body, dir_url)
                except Exception:
                    continue

        except Exception as e:
            logger.debug(f"Error scanning directory listing for {self.target}: {e}")

        return self.findings

    def _check_directory_listing(self, body: str, url: str) -> None:
        for indicator, description in DIRECTORY_INDICATORS:
            if indicator in body:
                evidence = self._extract_directory_listing_evidence(body, url)
                finding = create_finding(
                    target=self.target,
                    module="directory_listing",
                    title=f"Directory listing enabled: {url}",
                    evidence=evidence,
                    url=url,
                    status_code=200,
                    description=f"Directory listing is enabled at this URL. {description}",
                    tags=["directory-listing"],
                )
                self.findings.add(finding)
                return

        hrefs = re.findall(r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\']', body, re.I)
        if hrefs:
            dir_hrefs = [h for h in hrefs if h.endswith("/") and not h.startswith("?") and not h.startswith("#")]
            if len(dir_hrefs) > 5:
                file_hrefs = [h for h in hrefs if "." in h.rsplit("/", 1)[-1] and not h.startswith("?") and not h.startswith("#")]
                if len(dir_hrefs) > len(file_hrefs):
                    evidence = f"URL: {url}\nFound {len(dir_hrefs)} directories and {len(file_hrefs)} files"
                    finding = create_finding(
                        target=self.target,
                        module="directory_listing",
                        title=f"Possible directory listing: {url}",
                        evidence=evidence,
                        url=url,
                        status_code=200,
                        description="The directory appears to have directory listing enabled based on ratio of directories to files",
                        tags=["directory-listing", "suspected"],
                    )
                    self.findings.add(finding)

    def _extract_directory_listing_evidence(self, body: str, url: str) -> str:
        links = re.findall(r'<a\s+[^>]*href\s*=\s*["\']([^"\']+)["\']', body, re.I)
        visible_links = []
        for link in links:
            if link.startswith("?") or link.startswith("#") or link.startswith("javascript"):
                continue
            visible_links.append(link)

        evidence = f"URL: {url}\n"
        if visible_links:
            shown = visible_links[:30]
            evidence += f"Entries ({len(visible_links)}):\n" + "\n".join(f"  - {l}" for l in shown)
            if len(visible_links) > 30:
                evidence += f"\n  ... and {len(visible_links) - 30} more"
        else:
            evidence += "Directory listing content shown (links not extractable)"
        return evidence[:1500]
