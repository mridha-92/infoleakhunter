from __future__ import annotations

import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.errors")

ERROR_PATTERNS: list[tuple[str, str, str, str]] = [
    ("php_error", "PHP Error/Stack Trace",
     r"(?:Fatal error|Parse error|Warning|Notice|Deprecated):\s+.*?in\s+.*?\.php\s+on\s+line\s+\d+"),
    ("php_stack_trace", "PHP Stack Trace",
     r"#\d+\s+.*?\.php\(.*?\):\s+.*?\n"),
    ("python_traceback", "Python Traceback",
     r"Traceback\s*\(most recent call last\):.*?\n(?:.*\n)*?(?:\w+Error|\w+Exception)"),
    ("python_django_debug", "Django Debug Page",
     r"Django\s+version\s+\d+\.\d+.*?Python\s+executable"),
    ("python_flask_debug", "Flask Debug Page",
     r"Flask\s+DebugToolbar|The\s+debugger\s+caught\s+an\s+exception"),
    ("java_exception", "Java Exception",
     r"(?:Exception|Error) in thread \".*?\":?.*?(?:at\s+.*?\.java:\d+)"),
    ("java_stack_trace", "Java Stack Trace",
     r"\s+at\s+[\w.]+\([\w.]+\.java:\d+\)"),
    ("java_spring_error", "Spring Error/Whitelabel",
     r"Whitelabel\s+Error\s+Page|This\s+application\s+has\s+no\s+explicit\s+mapping"),
    ("aspnet_error", "ASP.NET Error",
     r"Server\s+Error\s+in\s+['\"]?[^'\"]*['\"]?\s+Application"),
    ("aspnet_ymlp", "ASP.NET Yellow Screen",
     r"<!--\s+Web\.config\s+Configuration\s+File\s+-->|\[HttpException\]:|Stack\s+Trace:"),
    ("aspnet_version", "ASP.NET Version",
     r"ASP\.NET\s+version:\s+\d+\.\d+\.\d+"),
    ("nodejs_error", "Node.js Error",
     r"(?:Error|TypeError|ReferenceError|SyntaxError):\s+.*?\n\s+at\s+\w+\s+\(.*?\.(?:js|ts|jsx|tsx):\d+:\d+\)"),
    ("nodejs_stack", "Node.js Stack Trace",
     r"\s+at\s+\w+\s+\(.*?node_modules.*?:\d+:\d+\)"),
    ("laravel_error", "Laravel Error",
     r"Laravel\s+[\d.]+\s+\(PHP\s+[\d.]+\)|Whoops\s*!\s*There\s+was\s+an\s+error"),
    ("rails_error", "Rails Error",
     r"Rails\s+root:\s+|Application\s+Trace|Framework\s+Trace|Full\s+Trace"),
    ("ruby_error", "Ruby Error",
     r"(?:NoMethodError|ArgumentError|RuntimeError|SyntaxError).*?\n.*?app/.*?:\d+:in"),
    ("go_panic", "Go Panic",
     r"panic:\s+.*?\n.*?goroutine\s+\d+.*?\n.*?\.go:\d+"),
    ("debug_mode", "Debug Mode Enabled",
     r"(?i)(debug\s*[=:]\s*true|APP_DEBUG\s*[=:]\s*true|DEBUG\s*=\s*True)"),
    ("sensitive_error_path", "Sensitive Path in Error",
     r"in\s+(?:/var/www|/home/|C:\\inetpub|/app|/srv|/usr/local|/opt)/\S+\.\w+:\d+"),
]

ERROR_SEVERITY_MAP = {
    "php_error": "Medium",
    "php_stack_trace": "Medium",
    "python_traceback": "High",
    "python_django_debug": "High",
    "python_flask_debug": "High",
    "java_exception": "High",
    "java_stack_trace": "Medium",
    "java_spring_error": "Medium",
    "aspnet_error": "Medium",
    "aspnet_ymlp": "Medium",
    "aspnet_version": "Low",
    "nodejs_error": "Medium",
    "nodejs_stack": "Medium",
    "laravel_error": "Medium",
    "rails_error": "Medium",
    "ruby_error": "Medium",
    "go_panic": "Medium",
    "debug_mode": "High",
    "sensitive_error_path": "High",
}


class ErrorDisclosureScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        try:
            status, headers, body, cookies = await self.http_client.check_url(self.target)

            if not body or status not in (200, 201, 202, 403, 404, 500):
                return self.findings

            for error_id, name, pattern_str, _ in ERROR_PATTERNS:
                try:
                    if error_id in ("php_stack_trace", "python_traceback", "nodejs_stack", "java_stack_trace"):
                        matches = list(re.finditer(pattern_str, body, re.MULTILINE))
                    else:
                        matches = list(re.finditer(pattern_str, body, re.MULTILINE | re.DOTALL))

                    if matches:
                        for match in matches[:3]:
                            evidence = match.group(0).strip()[:500]
                            if len(evidence) < 10:
                                continue

                            severity_str = ERROR_SEVERITY_MAP.get(error_id, "Medium")
                            finding = create_finding(
                                target=self.target,
                                module="errors",
                                title=f"Error disclosure: {name}",
                                evidence=evidence,
                                url=self.target,
                                status_code=status,
                                tags=["error", error_id.replace("_", "-")],
                            )
                            self.findings.add(finding)

                except re.error:
                    continue

        except Exception as e:
            logger.debug(f"Error scanning error disclosures for {self.target}: {e}")

        return self.findings
