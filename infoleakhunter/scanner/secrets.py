from __future__ import annotations

import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.entropy import EntropyCalculator
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.secrets")

SECRET_PATTERNS: list[tuple[str, str, str, re.Pattern[str], str]] = [
    ("aws_access_key", "AWS Access Key ID", "Critical",
     re.compile(r"(?<![A-Za-z0-9/+=])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9/+=])")),
    ("aws_secret_key", "AWS Secret Access Key", "Critical",
     re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])")),
    ("aws_session_token", "AWS Session Token", "Critical",
     re.compile(r"(?<![A-Za-z0-9/+=])(FQoGZXIvYXdzEH[\\w\\-!$%&'()*+,./:;<=>?@\\[\\]^`{|}~]{100,})(?![A-Za-z0-9/+=])")),
    ("azure_connection", "Azure Connection String", "Critical",
     re.compile(r"(?i)(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+)")),
    ("azure_subscription", "Azure Subscription Key", "High",
     re.compile(r"(?<![A-Za-z0-9])([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?![A-Za-z0-9])")),
    ("gcp_api_key", "GCP API Key", "High",
     re.compile(r"(?i)(AIza[0-9A-Za-z\-_]{35})")),
    ("gcp_service_account", "GCP Service Account", "Critical",
     re.compile(r"([a-zA-Z0-9-_]+@[a-zA-Z0-9-_]+\.iam\.gserviceaccount\.com)")),
    ("github_token", "GitHub Personal Access Token", "Critical",
     re.compile(r"(?i)(ghp_[0-9a-zA-Z]{36})")),
    ("github_oauth", "GitHub OAuth Access Token", "Critical",
     re.compile(r"(?i)(gho_[0-9a-zA-Z]{36})")),
    ("github_app_token", "GitHub App Token", "Critical",
     re.compile(r"(?i)(ghu_[0-9a-zA-Z]{36})")),
    ("github_refresh_token", "GitHub Refresh Token", "Critical",
     re.compile(r"(?i)(ghr_[0-9a-zA-Z]{36})")),
    ("gitlab_token", "GitLab Personal Token", "Critical",
     re.compile(r"(?i)(glpat-[0-9a-zA-Z\-_]{20,})")),
    ("stripe_pk", "Stripe Publishable Key", "High",
     re.compile(r"(?i)(pk_live_[0-9a-zA-Z]{24,})")),
    ("stripe_sk", "Stripe Secret Key", "Critical",
     re.compile(r"(?i)(sk_live_[0-9a-zA-Z]{24,})")),
    ("stripe_restricted", "Stripe Restricted Key", "Critical",
     re.compile(r"(?i)(rk_live_[0-9a-zA-Z]{24,})")),
    ("slack_token", "Slack API Token", "Critical",
     re.compile(r"(xox[baprs]-[0-9a-zA-Z\-]{10,})")),
    ("slack_webhook", "Slack Webhook URL", "High",
     re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/]+)")),
    ("firebase_key", "Firebase API Key", "High",
     re.compile(r"(?i)(AIza[0-9A-Za-z\-_]{35})")),
    ("firebase_db", "Firebase Database URL", "Medium",
     re.compile(r"(https://[a-zA-Z0-9-]+\.firebaseio\.com)")),
    ("twilio_sid", "Twilio Account SID", "Critical",
     re.compile(r"(AC[a-f0-9]{32})")),
    ("twilio_token", "Twilio Auth Token", "Critical",
     re.compile(r"(SK[a-f0-9]{32})")),
    ("sendgrid_key", "SendGrid API Key", "Critical",
     re.compile(r"(?i)(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})")),
    ("mailgun_key", "Mailgun API Key", "Critical",
     re.compile(r"(?i)(key-[a-f0-9]{32})")),
    ("mailchimp_key", "MailChimp API Key", "Critical",
     re.compile(r"(?i)([a-f0-9]{32}-us[0-9]{1,2})")),
    ("jwt_token", "JWT Token", "Critical",
     re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")),
    ("bearer_token", "Bearer Token", "High",
     re.compile(r"(?i)(bearer\s+[A-Za-z0-9\-._~+/]{20,})")),
    ("oauth_secret", "OAuth Client Secret", "Critical",
     re.compile(r"(?i)(client_secret['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9\-_!@#$%^&*()+=]{16,})")),
    ("private_key", "RSA Private Key", "Critical",
     re.compile(r"-----BEGIN\s?(?:RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE KEY-----")),
    ("ssh_key", "SSH Private Key", "Critical",
     re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
    ("pgp_private", "PGP Private Key", "Critical",
     re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----")),
    ("heroku_api", "Heroku API Key", "Critical",
     re.compile(r"(?i)([hH][eE][rR][oO][kK][uU]\s*[-:_]?\s*[aA][pP][iI]\s*[-:_]?\s*[kK][eE][yY]\s*[-:_]?\s*[A-Za-z0-9-]{20,})")),
    ("docker_auth", "Docker Auth Token", "Critical",
     re.compile(r"(?i)(docker_registry|docker\.password|docker\.token)[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9\-_=]{20,})")),
    ("npm_token", "NPM Auth Token", "Critical",
     re.compile(r"(?i)(npm_[A-Za-z0-9]{36})")),
    ("pypi_token", "PyPI API Token", "Critical",
     re.compile(r"(?i)(pypi-[A-Za-z0-9]{40,})")),
    ("database_url", "Database URL", "Critical",
     re.compile(r"(?i)((?:postgres|mysql|mssql|mongodb|redis)://[^\s\"'>)\]]+)")),
    ("json_web_key", "JSON Web Key", "High",
     re.compile(r"\{\s*\"kty\"\s*:\s*\"(?:RSA|EC|oct)\".*\"n\"\s*:\s*\"[A-Za-z0-9\-_+=/]+\"")),
    ("graphql_endpoint", "GraphQL Endpoint", "Medium",
     re.compile(r"(https?://[^\s\"'>)\]]+/graphql[^\s\"'>)\]]*)")),
    ("s3_url", "S3 URL", "Medium",
     re.compile(r"(https?://[a-zA-Z0-9.-]+\.s3\.amazonaws\.com/[^\s\"'>)\]]*)")),
    ("s3_bucket", "S3 Bucket", "Medium",
     re.compile(r"(s3://[a-zA-Z0-9._-]+)")),
]


class SecretScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        try:
            status, headers, body, cookies = await self.http_client.check_url(self.target)

            if not body or status not in (200, 201, 202):
                return self.findings

            if status == 200:
                self._find_secrets(body, self.target)

        except Exception as e:
            logger.debug(f"Error scanning secrets for {self.target}: {e}")

        return self.findings

    def _find_secrets(self, content: str, source_url: str) -> None:
        for secret_id, name, severity_str, pattern in SECRET_PATTERNS:
            try:
                for match in pattern.finditer(content):
                    secret = match.group(0).strip()

                    if len(secret) < 8 or len(secret) > 2048:
                        continue

                    if not self._is_real_secret(secret, name):
                        continue

                    if self.config.get("secrets", {}).get("entropy_enabled", True):
                        entropy = EntropyCalculator.shannon_entropy(secret)
                        threshold = self.config.get("secrets", {}).get("min_entropy", 3.5)

                        if secret_id in ("s3_url", "s3_bucket", "graphql_endpoint", "database_url"):
                            pass
                        elif "Key" in name or "Secret" in name or "Token" in name:
                            if entropy < threshold:
                                continue

                    evidence = self._extract_context(content, secret)
                    finding = create_finding(
                        target=self.target,
                        module="secrets",
                        title=f"{name} discovered",
                        evidence=evidence,
                        url=source_url,
                        status_code=200,
                        tags=["secret", secret_id.replace("_", "-")],
                    )
                    self.findings.add(finding)

            except re.error:
                continue

    def _is_real_secret(self, value: str, name: str) -> bool:
        common_values = {
            "REPLACE_ME", "CHANGE_ME", "YOUR_KEY_HERE", "YOUR_SECRET", "YOUR_TOKEN",
            "secret", "password", "changeme", "test", "example", "xxxxx",
            "your-aws-key", "your-api-key", "your-secret-key",
        }
        if value.strip().lower() in common_values:
            return False
        if value.count("x") / max(len(value), 1) > 0.5 and len(value) > 10:
            return False
        return True

    def _extract_context(self, content: str, target: str, window: int = 80) -> str:
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
