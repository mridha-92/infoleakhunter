from __future__ import annotations

import logging
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.sensitive_files")

SENSITIVE_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    ".env": [
        (r"(?i)(DB_|DATABASE_|PASSWORD|SECRET|API_KEY|TOKEN|AWS_|AZURE_|GCP_)", "Environment variable pattern found", "High"),
    ],
    "config.php": [
        (r"(?i)(password|passwd|pwd|secret|api_key|db_host|db_user)", "Configuration parameter found", "High"),
    ],
    "config.json": [
        (r"(?i)(\"password\"|\"secret\"|\"apiKey\"|\"connectionString\")", "Configuration secret found", "High"),
    ],
    "database.yml": [
        (r"(?i)(password|username|host|database)", "Database credential pattern found", "High"),
    ],
    "application.properties": [
        (r"(?i)(spring\.datasource\.|db\.|password=)", "Spring configuration parameter found", "High"),
    ],
    "web.config": [
        (r"(?i)(connectionString|password|user ID|initial catalog)", "Web configuration parameter found", "High"),
    ],
    ".htaccess": [
        (r"(?i)(AuthType|AuthName|AuthUserFile|Require|RewriteRule|Redirect)", "Access control configuration found", "Medium"),
    ],
    ".htpasswd": [
        (r"^[^:]+:[^:]+$", "Credentials file found", "Critical"),
    ],
    ".git/config": [
        (r"\[core\]|\[remote|\[branch", "Git repository configuration exposed", "Critical"),
    ],
    ".git/HEAD": [
        (r"ref:", "Git HEAD reference exposed", "Critical"),
    ],
    ".svn/entries": [
        (r"(?i)svn", "SVN metadata exposed", "High"),
    ],
    "robots.txt": [
        (r"(?i)(Disallow|Allow|Sitemap)", "Robots.txt file found", "Low"),
    ],
    "sitemap.xml": [
        (r"<urlset|<url>|<loc>", "Sitemap found", "Low"),
    ],
    "security.txt": [
        (r"(?i)(Contact|Encryption|Acknowledgments)", "Security.txt found", "Info"),
    ],
    "server-status": [
        (r"(?i)(Apache Server Status|Total Accesses|Server uptime)", "Server status page exposed", "Medium"),
    ],
    "composer.lock": [
        (r"\"name\":|packages", "Composer dependency list exposed", "Medium"),
    ],
    "package-lock.json": [
        (r"\"name\":|\"dependencies\":", "NPM dependency list exposed", "Medium"),
    ],
    "debug.log": [
        (r"(?i)(error|warning|fatal|exception|stack trace)", "Debug log exposed", "Critical"),
    ],
    "error.log": [
        (r"(?i)(error|warning|fatal|exception)", "Error log exposed", "High"),
    ],
}

SENSITIVE_FILE_DESCRIPTIONS: dict[str, str] = {
    ".env": "Environment file containing potential secrets and configuration",
    ".htaccess": "Apache access control configuration file",
    ".htpasswd": "Apache credentials file with hashed passwords",
    ".git/config": "Git repository configuration with repository metadata",
    ".svn": "Subversion version control metadata exposure",
    "robots.txt": "Search engine crawling rules (may disclose hidden paths)",
    "sitemap.xml": "Site structure and URL listing",
    "server-status": "Apache server status page exposing request details",
    "composer.lock": "PHP dependency list exposing library versions",
    "package-lock.json": "NPM dependency tree with exact versions",
    "debug.log": "Debug/error log with sensitive operational data",
}


class SensitiveFileScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        sensitive_paths = self.config.get("paths", {}).get("sensitive_files", [])
        if not sensitive_paths:
            logger.warning("No sensitive file paths configured")
            return self.findings

        for path in sensitive_paths:
            try:
                url = self.normalize_url(path)
                status, headers, body, cookies = await self.http_client.check_url(url, timeout=15)

                if status == 200 or status == 0:
                    continue

                if status in (301, 302, 307, 308):
                    continue

                if status != 200:
                    continue

                patterns = SENSITIVE_PATTERNS.get(path, [])
                matched = False
                for pattern, description, _ in patterns:
                    import re
                    if re.search(pattern, body):
                        evidence = self._extract_evidence(body, pattern)
                        title = f"Sensitive file exposed: {path}"
                        finding = create_finding(
                            target=self.target,
                            module="sensitive_file",
                            title=title,
                            evidence=evidence,
                            url=url,
                            status_code=status,
                            description=SENSITIVE_FILE_DESCRIPTIONS.get(path, f"Sensitive file {path} is publicly accessible"),
                            tags=["sensitive-file", path.replace("/", "-").replace(".", "-")],
                        )
                        self.findings.add(finding)
                        matched = True
                        break

                if not matched:
                    title = f"Sensitive file accessible: {path}"
                    finding = create_finding(
                        target=self.target,
                        module="sensitive_file",
                        title=title,
                        evidence=f"URL: {url} returned HTTP {status} ({len(body)} bytes)",
                        url=url,
                        status_code=status,
                        description=SENSITIVE_FILE_DESCRIPTIONS.get(path, f"Sensitive file {path} is publicly accessible"),
                        tags=["sensitive-file", path.replace("/", "-").replace(".", "-")],
                    )
                    self.findings.add(finding)

            except Exception as e:
                logger.debug(f"Error scanning {path} on {self.target}: {e}")

        return self.findings

    def _extract_evidence(self, body: str, pattern: str) -> str:
        import re
        matches = re.findall(pattern, body, re.I)
        if matches:
            lines = body.split("\n")
            matched_lines = []
            for i, line in enumerate(lines):
                if re.search(pattern, line, re.I):
                    start = max(0, i - 1)
                    end = min(len(lines), i + 2)
                    snippet = "\n".join(lines[start:end])
                    matched_lines.append(snippet)
                    if len(matched_lines) >= 5:
                        break
            return "\n...\n".join(matched_lines)[:2000]
        return body[:500]
