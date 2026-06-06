from __future__ import annotations

import logging
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.http_headers")

DISCLOSURE_HEADERS = {
    "Server": {
        "severity": "Medium",
        "description": "Web server software and version disclosed",
        "cwe": "CWE-200",
    },
    "X-Powered-By": {
        "severity": "Medium",
        "description": "Technology stack information disclosed",
        "cwe": "CWE-200",
    },
    "X-AspNet-Version": {
        "severity": "High",
        "description": "ASP.NET framework version disclosed",
        "cwe": "CWE-200",
    },
    "X-AspNetMvc-Version": {
        "severity": "High",
        "description": "ASP.NET MVC version disclosed",
        "cwe": "CWE-200",
    },
    "X-Runtime": {
        "severity": "Medium",
        "description": "Ruby/Rails runtime version disclosed",
        "cwe": "CWE-200",
    },
    "X-Version": {
        "severity": "Medium",
        "description": "Application version information disclosed",
        "cwe": "CWE-200",
    },
    "X-Generator": {
        "severity": "Low",
        "description": "CMS/generator information disclosed",
        "cwe": "CWE-200",
    },
    "Via": {
        "severity": "Low",
        "description": "Proxy/gateway information disclosed",
        "cwe": "CWE-200",
    },
    "X-Backend": {
        "severity": "High",
        "description": "Backend server routing disclosed",
        "cwe": "CWE-200",
    },
    "X-Backend-Server": {
        "severity": "High",
        "description": "Backend server name disclosed",
        "cwe": "CWE-200",
    },
    "X-Debug-Token": {
        "severity": "High",
        "description": "Debug token exposed in response headers",
        "cwe": "CWE-200",
    },
    "X-Debug-Token-Link": {
        "severity": "Critical",
        "description": "Debug toolbar URL exposed",
        "cwe": "CWE-200",
    },
    "X-Drupal-Cache": {
        "severity": "Low",
        "description": "Drupal caching information disclosed",
        "cwe": "CWE-200",
    },
    "X-Drupal-Dynamic-Cache": {
        "severity": "Low",
        "description": "Drupal dynamic cache status disclosed",
        "cwe": "CWE-200",
    },
    "X-Varnish": {
        "severity": "Low",
        "description": "Varnish caching infrastructure disclosed",
        "cwe": "CWE-200",
    },
    "X-Cache": {
        "severity": "Low",
        "description": "CDN/caching layer information disclosed",
        "cwe": "CWE-200",
    },
    "CF-Ray": {
        "severity": "Low",
        "description": "Cloudflare ray identifier disclosed",
        "cwe": "CWE-200",
    },
    "OpenSSL": {
        "severity": "Medium",
        "description": "OpenSSL version disclosed in headers",
        "cwe": "CWE-200",
    },
}

ADDITIONAL_LEAKAGE_HEADERS = [
    "X-Amz-Id-2",
    "X-Amz-Request-Id",
    "X-Amz-Cf-Id",
    "X-Server-Powered-By",
    "X-Server-Name",
    "X-Server-Host",
    "X-Served-By",
    "X-Served-From",
    "X-Backend-Host",
    "X-Proxy-Cache",
    "X-Proxy-Server",
    "X-Host",
    "X-Cluster-Name",
    "X-Node-Name",
    "X-Application-Context",
    "X-Envoy",
    "X-Kong",
    "X-Tyk",
]


class HTTPHeaderScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        try:
            url = self.target
            status, headers, body, cookies = await self.http_client.check_url(url)

            if not headers:
                logger.debug(f"No headers returned for {self.target}")
                return self.findings

            for header, info in DISCLOSURE_HEADERS.items():
                if header in headers:
                    value = headers[header]
                    if value.strip():
                        evidence = f"{header}: {value}"
                        finding = create_finding(
                            target=self.target,
                            module="http_header",
                            title=f"Information disclosure via {header} header",
                            evidence=evidence,
                            url=url,
                            status_code=status,
                            description=info["description"],
                            tags=["header", header.lower().replace("-", "-")],
                        )
                        self.findings.add(finding)

            for header in ADDITIONAL_LEAKAGE_HEADERS:
                if header in headers:
                    value = headers[header]
                    evidence = f"{header}: {value}"
                    finding = create_finding(
                        target=self.target,
                        module="http_header",
                        title=f"Infrastructure information disclosed via {header}",
                        evidence=evidence,
                        url=url,
                        status_code=status,
                        description=f"Internal infrastructure information disclosed via the {header} response header",
                        tags=["header", "infrastructure", header.lower().replace("-", "-")],
                    )
                    self.findings.add(finding)

        except Exception as e:
            logger.debug(f"Error scanning HTTP headers for {self.target}: {e}")

        return self.findings
