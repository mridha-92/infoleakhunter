from __future__ import annotations

import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.source_code")

COMMENT_PATTERNS = {
    "html_comment": (r"<!--(.*?)-->", "HTML comment contains"),
    "todo": (r"(?i)(TODO|FIXME|XXX|HACK|BUG|WORKAROUND|TEMP|HARDCODE)\b[^.]*\.?", "Development comment found"),
    "internal_url": (
        r"(https?://(?:dev|stage|staging|qa|test|uat|internal|admin|private|local|jira|confluence|jenkins|gitlab|github|bitbucket)\.[^\s\"'>)\]]+)",
        "Internal/development URL exposed",
    ),
    "api_endpoint": (
        r"(/api/v[0-9]+/[^\s\"'>)\]]+|/graphql[^\s\"'>)\]]*|/rest/v[0-9]+/[^\s\"'>)\]]+)",
        "API endpoint exposed in source",
    ),
    "admin_path": (
        r"(/admin|/administrator|/wp-admin|/backend|/manager|/console|/dashboard|/panel|/cpanel)[/\s\"'>)\]])",
        "Admin panel path exposed",
    ),
    "email": (
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "Email address exposed in source",
    ),
    "phone": (
        r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}",
        "Phone number exposed in source",
    ),
    "ip_address": (
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "Internal IP address exposed",
    ),
    "internal_hostname": (
        r"\b(?:dev-|stage-|qa-|test-|uat-)[a-zA-Z0-9-]+\.(?:local|internal|corp|lan)\b",
        "Internal hostname exposed",
    ),
    "s3_bucket": (
        r"\b[a-zA-Z0-9.-]+\.s3\.amazonaws\.com\b",
        "S3 bucket URL exposed",
    ),
    "s3_bucket_name": (
        r"\b(?:s3://|amazonaws\.com/)[a-zA-Z0-9._-]+",
        "S3 bucket reference exposed",
    ),
    "connection_string": (
        r"(?i)(mongodb://|postgresql://|mysql://|redis://|amqp://|rabbitmq://)[^\s\"'>)\]]+",
        "Database connection string exposed",
    ),
}

EXCLUDED_EMAIL_DOMAINS = [
    "example.com", "example.org", "example.net", "domain.com",
    "yourdomain.com", "test.com", "yourcompany.com",
]


class SourceCodeScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        try:
            url = self.target
            status, headers, body, cookies = await self.http_client.check_url(url)

            if not body or status not in (200, 201, 202):
                return self.findings

            for finding_type, (pattern, description) in COMMENT_PATTERNS.items():
                try:
                    matches = re.findall(pattern, body, re.MULTILINE | re.DOTALL)
                    if not matches:
                        continue

                    seen = set()
                    for match in matches[:20]:
                        content = match.strip() if isinstance(match, str) else match[0].strip()
                        if not content or len(content) < 3:
                            continue

                        if finding_type == "email":
                            domain = content.split("@")[-1] if "@" in content else ""
                            if domain in EXCLUDED_EMAIL_DOMAINS:
                                continue

                        if finding_type == "ip_address":
                            import ipaddress
                            try:
                                ip_obj = ipaddress.ip_address(content)
                                if not ip_obj.is_private and not ip_obj.is_loopback:
                                    continue
                            except ValueError:
                                continue

                        content_hash = content[:100]
                        if content_hash in seen:
                            continue
                        seen.add(content_hash)

                        title = f"{description}: {content[:80]}"
                        evidence = self._extract_context(body, content)

                        severity_map = {
                            "todo": "Low",
                            "internal_url": "Medium",
                            "api_endpoint": "Medium",
                            "admin_path": "Medium",
                            "connection_string": "Critical",
                            "s3_bucket": "High",
                            "internal_hostname": "Low",
                            "email": "Low",
                        }
                        mapped_severity = severity_map.get(finding_type, "Low")
                        mapped_module = "source_code"

                        finding = create_finding(
                            target=self.target,
                            module=mapped_module,
                            title=title,
                            evidence=evidence,
                            url=url,
                            status_code=status,
                            tags=["source-code", finding_type],
                        )
                        self.findings.add(finding)

                except re.error:
                    continue

        except Exception as e:
            logger.debug(f"Error scanning source code for {self.target}: {e}")

        return self.findings

    def _extract_context(self, body: str, content: str, window: int = 50) -> str:
        idx = body.find(content)
        if idx == -1:
            return content[:500]
        start = max(0, idx - window)
        end = min(len(body), idx + len(content) + window)
        snippet = body[start:end]
        if start > 0:
            snippet = "... " + snippet
        if end < len(body):
            snippet = snippet + " ..."
        return snippet[:1000]
