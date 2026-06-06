from __future__ import annotations

import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.cloud_exposure")

CLOUD_PATTERNS: list[tuple[str, str, str, str]] = [
    ("aws_s3_bucket_url", "AWS S3 Bucket URL", "Medium",
     r"(https?://[a-zA-Z0-9.-]+\.s3\.amazonaws\.com(?:/[^\s\"'>)\]\)]*)?)"),
    ("aws_s3_bucket_arn", "AWS S3 Bucket ARN", "Medium",
     r"arn:aws:s3:::[a-zA-Z0-9.-]+"),
    ("aws_s3_bucket_ref", "AWS S3 Bucket Reference", "Low",
     r"(?i)(['\"]bucket['\"]\s*[:=]\s*['\"][a-zA-Z0-9._-]+['\"])"),
    ("aws_ec2_ref", "AWS EC2 Reference", "Low",
     r"(?i)(ec2-[0-9]+-[0-9]+-[0-9]+-[0-9]+\.(?:compute|us-east|us-west|eu-west|eu-central|ap-southeast|ap-northeast|sa-east)\.amazonaws\.com)"),
    ("aws_rds_ref", "AWS RDS Reference", "Medium",
     r"(?i)([a-zA-Z0-9-]+\.(?:rds|rds\.amazonaws)\.com)"),
    ("aws_elb_ref", "AWS ELB Reference", "Low",
     r"(?i)([a-zA-Z0-9-]+-\d+\.(?:us-east|us-west|eu-west|eu-central|ap-southeast|ap-northeast)\.elb\.amazonaws\.com)"),
    ("aws_cloudfront", "AWS CloudFront Distribution", "Medium",
     r"(https?://[a-zA-Z0-9]+\.cloudfront\.net(?:/[^\s\"'>)\]\)]*)?)"),
    ("aws_lambda", "AWS Lambda Function", "Medium",
     r"(arn:aws:lambda:[a-z0-9-]+:\d+:function:[a-zA-Z0-9-_]+)"),
    ("aws_iam_arn", "AWS IAM ARN", "High",
     r"(arn:aws:iam::\d+:(?:user|role|group|policy)/[a-zA-Z0-9-_]+)"),
    ("azure_storage", "Azure Storage Account", "Medium",
     r"(https?://[a-zA-Z0-9]+\.(?:blob|file|queue|table)\.core\.windows\.net(?:/[^\s\"'>)\]\)]*)?)"),
    ("azure_appservice", "Azure App Service", "Medium",
     r"(https?://[a-zA-Z0-9-]+\.azurewebsites\.net(?:/[^\s\"'>)\]\)]*)?)"),
    ("azure_db", "Azure Database", "Medium",
     r"(https?://[a-zA-Z0-9-]+\.database\.windows\.net(?:/[^\s\"'>)\]\)]*)?)"),
    ("azure_redis", "Azure Redis Cache", "Medium",
     r"(https?://[a-zA-Z0-9-]+\.redis\.cache\.windows\.net(?:/[^\s\"'>)\]\)]*)?)"),
    ("azure_cdn", "Azure CDN", "Medium",
     r"(https?://[a-zA-Z0-9-]+\.azureedge\.net(?:/[^\s\"'>)\]\)]*)?)"),
    ("azure_vm", "Azure VM", "Low",
     r"(https?://[a-zA-Z0-9-]+\.(?:cloudapp|westus|eastus|westeurope|northeurope|southeastasia)\.azure\.com)"),
    ("gcp_storage", "GCP Storage Bucket", "Medium",
     r"(https?://storage\.googleapis\.com/[a-zA-Z0-9_-]+(?:/[^\s\"'>)\]\)]*)?)"),
    ("gcp_cloudfunction", "GCP Cloud Function", "Medium",
     r"(https?://[a-zA-Z0-9-]+\.cloudfunctions\.net(?:/[^\s\"'>)\]\)]*)?)"),
    ("gcp_appengine", "GCP App Engine", "Medium",
     r"(https?://[a-zA-Z0-9-]+\.appspot\.com(?:/[^\s\"'>)\]\)]*)?)"),
    ("gcp_compute", "GCP Compute Engine", "Low",
     r"(https?://[a-zA-Z0-9-]+\.(?:us-central1|europe-west1|asia-east1)\.compute\.amazonaws\.com)"),
    ("gcp_bigquery", "GCP BigQuery", "Medium",
     r"(?i)(['\"]projectId['\"]\s*[:=]\s*['\"][a-zA-Z0-9-]+['\"][\s,]*['\"]datasetId['\"])"),
    ("digitalocean", "DigitalOcean", "Low",
     r"(https?://[a-zA-Z0-9-]+\.(?:digitaloceanspaces|ondigitalocean)\.com(?:/[^\s\"'>)\]\)]*)?)"),
    ("heroku", "Heroku App", "Low",
     r"(https?://[a-zA-Z0-9-]+\.herokuapp\.com(?:/[^\s\"'>)\]\)]*)?)"),
    ("firebase", "Firebase Project", "Medium",
     r"(https?://[a-zA-Z0-9-]+\.firebaseio\.com(?:/[^\s\"'>)\]\)]*)?)"),
    ("firebase_app", "Firebase App", "Medium",
     r"(https?://[a-zA-Z0-9-]+\.firebaseapp\.com(?:/[^\s\"'>)\]\)]*)?)"),
    ("cloud_generic", "Cloud Generic Reference", "Low",
     r"(?i)(['\"](?:cloud|aws|azure|gcp|gke|eks|aks)['\"]\s*[:=])"),
]

SENSITIVE_CLOUD_PATTERNS: list[tuple[str, str, str]] = [
    ("aws_account_id", "AWS Account ID", r"(arn:aws:iam::(\d{12}):)"),
    ("aws_user_arn", "AWS User ARN", r"(arn:aws:iam::\d{12}:user/[a-zA-Z0-9-_]+)"),
    ("azure_subscription_id_pattern", "Azure Subscription ID", r"(subscriptions/([a-f0-9\-]{36})/)"),
    ("gcp_project_id", "GCP Project ID", r"(projects/([a-zA-Z0-9\-]{6,30})/)"),
]


class CloudExposureScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        try:
            status, headers, body, cookies = await self.http_client.check_url(self.target)

            if not body or status not in (200, 201, 202):
                return self.findings

            for cloud_id, name, severity_str, pattern in CLOUD_PATTERNS:
                try:
                    matches = re.findall(pattern, body, re.I)
                    if matches:
                        for match in matches[:5]:
                            evidence = self._extract_context(body, match if isinstance(match, str) else match[0])
                            finding = create_finding(
                                target=self.target,
                                module="cloud_exposure",
                                title=f"Cloud resource reference: {name}",
                                evidence=evidence,
                                url=self.target,
                                status_code=status,
                                tags=["cloud", cloud_id.replace("_", "-")],
                            )
                            self.findings.add(finding)
                except re.error:
                    continue

            for cloud_id, name, pattern in SENSITIVE_CLOUD_PATTERNS:
                try:
                    matches = re.findall(pattern, body, re.I)
                    if matches:
                        for match in matches[:3]:
                            evidence = self._extract_context(body, match if isinstance(match, str) else match[0])
                            finding = create_finding(
                                target=self.target,
                                module="cloud_exposure",
                                title=f"Sensitive cloud identifier: {name}",
                                evidence=evidence,
                                url=self.target,
                                status_code=status,
                                tags=["cloud", "sensitive", cloud_id.replace("_", "-")],
                            )
                            self.findings.add(finding)
                except re.error:
                    continue

        except Exception as e:
            logger.debug(f"Error scanning cloud exposure for {self.target}: {e}")

        return self.findings

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
