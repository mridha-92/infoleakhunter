from __future__ import annotations

import re
from typing import Any

from infoleakhunter.models.finding import Confidence, Finding, Severity

CWE_MAPPING: dict[str, str] = {
    "sensitive_file": "CWE-530",
    "http_header": "CWE-200",
    "source_code": "CWE-540",
    "javascript": "CWE-312",
    "secrets": "CWE-798",
    "errors": "CWE-209",
    "directory_listing": "CWE-548",
    "api_docs": "CWE-497",
    "git_exposure": "CWE-200",
    "cloud_exposure": "CWE-200",
    "metadata": "CWE-200",
    "dns": "CWE-200",
}

OWASP_MAPPING: dict[str, str] = {
    "sensitive_file": "OWASP:API8",
    "http_header": "OWASP:API4",
    "source_code": "OWASP:API8",
    "javascript": "OWASP:API8",
    "secrets": "OWASP:API8",
    "errors": "OWASP:API7",
    "directory_listing": "OWASP:API8",
    "api_docs": "OWASP:API9",
    "git_exposure": "OWASP:API8",
    "cloud_exposure": "OWASP:API8",
    "metadata": "OWASP:API8",
    "dns": "OWASP:API3",
}

CVSS_ESTIMATES: dict[str, dict[str, str]] = {
    "sensitive_file": {"Critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:F/RL:O/RC:C"},
    "http_header": {"High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:P/RL:O/RC:C"},
    "source_code": {"High": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N/E:F/RL:O/RC:C"},
    "secrets": {"Critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:F/RL:O/RC:C"},
    "errors": {"Medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:P/RL:O/RC:C"},
    "directory_listing": {"Medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:P/RL:O/RC:C"},
    "git_exposure": {"Critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N/E:H/RL:O/RC:C"},
}

RECOMMENDATIONS: dict[str, str] = {
    "sensitive_file": "Remove sensitive files from the web root. Store configuration and credentials outside the document root. Use environment variables for secrets.",
    "http_header": "Configure the web server to suppress verbose headers. Use 'server_tokens off' (Nginx) or 'ServerTokens Prod' (Apache).",
    "source_code": "Remove sensitive comments from production code. Use build processes to strip development artifacts. Review and sanitize all output.",
    "javascript": "Never embed secrets in client-side code. Use server-side proxies. Implement strict CSP headers. Rotate any exposed credentials immediately.",
    "secrets": "Immediately revoke and rotate exposed credentials. Use a vault solution. Implement secret scanning in CI/CD. Never hardcode secrets.",
    "errors": "Disable debug mode in production. Implement custom error pages. Log errors server-side only. Never expose stack traces to clients.",
    "directory_listing": "Disable directory listing on the web server. Use index files or 'Options -Indexes' (Apache) or 'autoindex off' (Nginx).",
    "api_docs": "Restrict access to API documentation. Use authentication. Do not expose internal API schemas to unauthenticated users.",
    "git_exposure": "Remove .git directory from production. Block access via web server rules. Never deploy with version control metadata.",
    "cloud_exposure": "Review cloud resource configurations. Implement proper IAM policies. Use resource tagging and monitoring.",
    "metadata": "Remove metadata from public files. Use automated tools to sanitize documents before publishing.",
    "dns": "Review DNS records for exposed internal information. Remove unnecessary TXT records. Use minimal disclosure in DNS.",
}


def calculate_severity(module: str, context: dict[str, Any] | None = None) -> Severity:
    context = context or {}
    default_severities: dict[str, str] = {
        "secrets": "Critical",
        "git_exposure": "Critical",
        "sensitive_file": "High",
        "cloud_exposure": "High",
        "http_header": "Medium",
        "source_code": "Medium",
        "errors": "Medium",
        "directory_listing": "Medium",
        "api_docs": "Medium",
        "javascript": "Medium",
        "metadata": "Low",
        "dns": "Low",
    }
    severity_str = default_severities.get(module, "Medium")

    if context:
        confidence = context.get("confidence", Confidence.MEDIUM)
        if confidence == Confidence.LOW or confidence == Confidence.SPECULATIVE:
            base_idx = list(Severity).index(Severity(severity_str))
            lowered_idx = min(base_idx + 1, len(Severity) - 1)
            severity_str = list(Severity)[lowered_idx].value

    return Severity(severity_str)


def calculate_confidence(module: str, evidence: str, status_code: int | None = None) -> Confidence:
    if status_code and status_code == 200:
        if module in ("sensitive_file", "git_exposure", "secrets"):
            return Confidence.CERTAIN
        return Confidence.HIGH
    if status_code and status_code in (301, 302, 307, 308):
        return Confidence.MEDIUM
    if evidence and len(evidence) > 50:
        return Confidence.MEDIUM
    if evidence and len(evidence) > 10:
        return Confidence.LOW
    return Confidence.SPECULATIVE


def get_cwe(module: str) -> str:
    return CWE_MAPPING.get(module, "CWE-200")


def get_owasp(module: str) -> str:
    return OWASP_MAPPING.get(module, "OWASP:API8")


def get_recommendation(module: str) -> str:
    return RECOMMENDATIONS.get(module, "Review and remediate the identified information disclosure.")


def get_cvss_estimate(module: str, severity: Severity) -> str:
    module_estimates = CVSS_ESTIMATES.get(module, {})
    return module_estimates.get(severity.value, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:P/RL:O/RC:C")


def create_finding(
    target: str,
    module: str,
    title: str,
    evidence: str,
    url: str = "",
    status_code: int | None = None,
    description: str = "",
    tags: list[str] | None = None,
    context: dict[str, Any] | None = None,
) -> Finding:
    confidence = calculate_confidence(module, evidence, status_code)
    severity = calculate_severity(module, context or {"confidence": confidence})
    cwe = get_cwe(module)
    owasp = get_owasp(module)
    recommendation = get_recommendation(module)
    cvss = get_cvss_estimate(module, severity)

    return Finding(
        target=target,
        module=module,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=evidence,
        cwe=cwe,
        owasp=owasp,
        recommendation=recommendation,
        url=url,
        description=description,
        cvss_estimate=cvss,
        tags=tags or [],
    )
