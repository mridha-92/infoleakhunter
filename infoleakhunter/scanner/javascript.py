from __future__ import annotations

import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.entropy import EntropyCalculator
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.javascript")

JS_FILE_PATTERN = re.compile(r'<script[^>]+src=["\']([^"\']+\.(?:js|min\.js|bundle\.js))["\']', re.I)

SECRET_PATTERNS_IN_JS: list[tuple[str, str, re.Pattern[str], str]] = [
    ("aws_key", "AWS Access Key", re.compile(r"(?i)(AKIA[0-9A-Z]{16})")),
    ("aws_secret", "AWS Secret Key", re.compile(r"(?i)(['\"])[A-Za-z0-9/+=]{40}\1")),
    ("google_api", "Google API Key", re.compile(r"(?i)(AIza[0-9A-Za-z\-_]{35})")),
    ("google_oauth", "Google OAuth", re.compile(r"(?i)([0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com)")),
    ("firebase", "Firebase URL", re.compile(r"(?i)([a-zA-Z0-9-]+\.firebaseio\.com)")),
    ("stripe_pk", "Stripe Publishable Key", re.compile(r"(?i)(pk_live_[0-9A-Za-z]{24,})")),
    ("stripe_sk", "Stripe Secret Key", re.compile(r"(?i)(sk_live_[0-9A-Za-z]{24,})")),
    ("slack_token", "Slack Token", re.compile(r"(?i)(xox[baprs]-[0-9A-Za-z-]{10,})")),
    ("github_token", "GitHub Token", re.compile(r"(?i)(ghp_[0-9A-Za-z]{36})")),
    ("github_old", "GitHub Old Token", re.compile(r"(?i)(gho_[0-9A-Za-z]{36})")),
    ("gitlab_token", "GitLab Token", re.compile(r"(?i)(glpat-[0-9A-Za-z\-_]{20,})")),
    ("jwt", "JWT Token", re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("bearer", "Bearer Token", re.compile(r"(?i)(bearer\s+[A-Za-z0-9\-._~+/]{20,})")),
    ("basic_auth", "Basic Auth", re.compile(r"(?i)(basic\s+[A-Za-z0-9+/=]{20,})")),
    ("twilio_sid", "Twilio SID", re.compile(r"(?i)(AC[a-f0-9]{32})")),
    ("twilio_token", "Twilio Token", re.compile(r"(?i)(SK[a-f0-9]{32})")),
    ("sendgrid", "SendGrid Key", re.compile(r"(?i)(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})")),
    ("mapbox", "MapBox Token", re.compile(r"(?i)(pk\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("facebook_secret", "Facebook App Secret", re.compile(r"(?i)([0-9a-f]{32})")),
    ("recaptcha", "reCAPTCHA Key", re.compile(r"(?i)(6L[0-9A-Za-z_-]{38})")),
    ("sentry_dsn", "Sentry DSN", re.compile(r"(https://[a-f0-9]{32}@[a-f0-9]{32}\.ingest\.sentry\.io/\d+)")),
]

INTERNAL_ENDPOINT_PATTERNS = [
    (re.compile(r"(https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(:\d+)?(/[^\s\"'>)\]]*)?)"), "Internal endpoint"),
    (re.compile(r"(https?://[a-zA-Z0-9-]+\.(?:local|internal|corp|lan|dev|stage|staging|qa|test|uat)(:\d+)?(/[^\s\"'>)\]]*)?)"), "Internal hostname"),
    (re.compile(r"(wss?://[^\s\"'>)\]]+)"), "WebSocket URL"),
    (re.compile(r"(https?://[a-zA-Z0-9-]+\.(?:s3|s3-[a-z0-9-]+)\.amazonaws\.com/[^\s\"'>)\]]+)"), "AWS S3 endpoint"),
    (re.compile(r"(https?://[a-zA-Z0-9-]+\.(?:execute-api|lambda)\.(?:[a-z0-9-]+)\.amazonaws\.com/[^\s\"'>)\]]*)"), "AWS API Gateway"),
    (re.compile(r"(https?://[a-zA-Z0-9-]+\.cloudfront\.net/[^\s\"'>)\]]*)"), "CloudFront distribution"),
    (re.compile(r"(https?://[a-zA-Z0-9-]+\.azurewebsites\.net/[^\s\"'>)\]]*)"), "Azure App Service"),
    (re.compile(r"(https?://[a-zA-Z0-9-]+\.azureedge\.net/[^\s\"'>)\]]*)"), "Azure CDN"),
    (re.compile(r"(https?://[a-zA-Z0-9-]+\.cloudfunctions\.net/[^\s\"'>)\]]*)"), "Google Cloud Function"),
    (re.compile(r"(https?://storage\.googleapis\.com/[^\s\"'>)\]]+)"), "GCP Storage"),
    (re.compile(r"(https?://[a-zA-Z0-9-]+\.(?:graphql|playground|api)\.[^\s\"'>)\]]+)"), "GraphQL/API endpoint"),
]

ENV_VAR_PATTERN = re.compile(r"(?i)(process\.env\.([A-Za-z_][A-Za-z0-9_]*)|import\.meta\.env\.([A-Za-z_][A-Za-z0-9_]*)|__ENV__\.([A-Za-z_][A-Za-z0-9_]*))")
CONFIG_PATTERN = re.compile(r"(?i)(['\"](apiKey|apiSecret|api_key|api_secret|secret|password|token|privateKey|private_key)['\"]\s*[:=]\s*['\"]([^'\"]{8,})['\"])")
CLOUD_REF_PATTERN = re.compile(r"(?i)(['\"](?:project_id|projectId|project_number|bucket|storageBucket|authDomain|databaseURL|messagingSenderId|appId|measurementId)['\"]\s*[:=]\s*['\"]([^'\"]+)['\"])")


class JavaScriptScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        try:
            status, headers, body, cookies = await self.http_client.check_url(self.target)

            if not body or status not in (200, 201, 202):
                return self.findings

            js_urls = self._extract_js_urls(body)

            for js_url in js_urls[:50]:
                await self._analyze_js(js_url)

            inline_scripts = self._extract_inline_scripts(body)
            for script in inline_scripts:
                self._analyze_content(script, self.target)

        except Exception as e:
            logger.debug(f"Error in JavaScript scanning for {self.target}: {e}")

        return self.findings

    def _extract_js_urls(self, html: str) -> list[str]:
        urls = []
        for match in JS_FILE_PATTERN.finditer(html):
            src = match.group(1)
            if src.startswith("http://") or src.startswith("https://"):
                urls.append(src)
            elif src.startswith("//"):
                from urllib.parse import urlparse
                parsed = urlparse(self.target)
                urls.append(f"{parsed.scheme}:{src}")
            elif src.startswith("/"):
                from urllib.parse import urlparse
                parsed = urlparse(self.target)
                urls.append(f"{parsed.scheme}://{parsed.netloc}{src}")
            else:
                urls.append(f"{self.target.rstrip('/')}/{src.lstrip('/')}")
        return urls

    def _extract_inline_scripts(self, html: str) -> list[str]:
        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.I)
        return [s.strip() for s in scripts if s.strip()]

    async def _analyze_js(self, url: str) -> None:
        try:
            status, headers, body, cookies = await self.http_client.check_url(url)
            if status == 200 and body:
                self._analyze_content(body, url)
        except Exception as e:
            logger.debug(f"Error fetching JS {url}: {e}")

    def _analyze_content(self, content: str, source_url: str) -> None:
        for secret_id, name, pattern, _ in SECRET_PATTERNS_IN_JS:
            for match in pattern.finditer(content):
                secret = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                if len(secret) < 8:
                    continue
                entropy_ok = True
                if self.config.get("secrets", {}).get("entropy_enabled", True):
                    entropy = EntropyCalculator.shannon_entropy(secret)
                    threshold = self.config.get("secrets", {}).get("min_entropy", 3.5)
                    entropy_ok = entropy >= threshold

                if not entropy_ok:
                    continue

                evidence = self._extract_context(content, secret)
                finding = create_finding(
                    target=self.target,
                    module="javascript",
                    title=f"{name} exposed in JavaScript",
                    evidence=evidence,
                    url=source_url,
                    tags=["javascript", "secret", secret_id],
                )
                self.findings.add(finding)

        for endpoint_pattern, description in INTERNAL_ENDPOINT_PATTERNS:
            for match in endpoint_pattern.finditer(content):
                endpoint = match.group(1)
                evidence = self._extract_context(content, endpoint)
                finding = create_finding(
                    target=self.target,
                    module="javascript",
                    title=f"{description} found in JavaScript: {endpoint[:80]}",
                    evidence=evidence,
                    url=source_url,
                    tags=["javascript", "endpoint"],
                )
                self.findings.add(finding)

        for match in ENV_VAR_PATTERN.finditer(content):
            var_name = match.group(2) or match.group(3) or match.group(4) or ""
            evidence = self._extract_context(content, match.group(0))
            finding = create_finding(
                target=self.target,
                module="javascript",
                title=f"Environment variable reference: {var_name}",
                evidence=evidence,
                url=source_url,
                tags=["javascript", "env-var", var_name.lower()],
            )
            self.findings.add(finding)

        for match in CONFIG_PATTERN.finditer(content):
            key = match.group(2)
            value = match.group(3)
            evidence = self._extract_context(content, match.group(0))
            if self.config.get("secrets", {}).get("entropy_enabled", True):
                entropy = EntropyCalculator.shannon_entropy(value)
                threshold = self.config.get("secrets", {}).get("min_entropy", 3.5)
                if entropy < threshold:
                    continue
            finding = create_finding(
                target=self.target,
                module="javascript",
                title=f"Configuration secret found: {key}",
                evidence=evidence,
                url=source_url,
                tags=["javascript", "config", key.lower()],
            )
            self.findings.add(finding)

    def _extract_context(self, content: str, target: str, window: int = 60) -> str:
        idx = content.find(target)
        if idx == -1:
            return target[:500]
        start = max(0, idx - window)
        end = min(len(content), idx + len(target) + window)
        snippet = content[start:end]
        if start > 0:
            snippet = "... " + snippet
        if end < len(content):
            snippet = snippet + " ..."
        return snippet[:1000]
