from __future__ import annotations

import logging
import re
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.scanner.base import BaseScanner
from infoleakhunter.utils.severity import create_finding

logger = logging.getLogger("infoleakhunter.scanner.api_docs")

API_DOC_PATHS = [
    "api/documentation",
    "api/docs",
    "api/swagger",
    "api/openapi",
    "api/v1/documentation",
    "api/v2/documentation",
    "api/v3/documentation",
    "api/graphql",
    "graphql",
    "graphiql",
    "graphql/playground",
    "swagger",
    "swagger/",
    "swagger-ui",
    "swagger-ui.html",
    "swagger-resources",
    "v2/api-docs",
    "v3/api-docs",
    "swagger.json",
    "openapi.json",
    "swagger.yaml",
    "openapi.yaml",
    "api/swagger.json",
    "api/openapi.json",
    "api-spec",
    "api-specification",
    "api/redoc",
    "redoc",
    "docs",
    "documentation",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
]

API_INDICATORS = {
    "swagger-ui": [
        (r"swagger-ui", "Swagger UI detected"),
        (r"SwaggerUIBundle", "Swagger UI bundle detected"),
        (r"SwaggerUIStandalonePreset", "Swagger UI standalone preset detected"),
        (r"swagger\.js", "Swagger JavaScript detected"),
    ],
    "swagger-json": [
        (r"\{.*\"swagger\"\s*:\s*\"", "Swagger JSON specification"),
        (r"\"openapi\"\s*:\s*\"", "OpenAPI specification"),
        (r"\"info\"\s*:\s*\{.*\"version\"", "API info object"),
        (r"\"paths\"\s*:\s*\{", "API paths defined"),
    ],
    "redoc": [
        (r"<redoc>", "Redoc detected"),
        (r"redoc\.init", "Redoc initialization detected"),
        (r"redoc\.min\.js", "Redoc JavaScript detected"),
    ],
    "graphql": [
        (r"query\s+\w+\s*\{", "GraphQL query detected"),
        (r"mutation\s+\w+\s*\{", "GraphQL mutation detected"),
        (r"subscription\s+\w+\s*\{", "GraphQL subscription detected"),
        (r"\"__schema\"", "GraphQL schema introspection detected"),
        (r"graphql", "GraphQL endpoint reference"),
    ],
    "graphiql": [
        (r"GraphiQL", "GraphiQL IDE detected"),
        (r"graphiql", "GraphiQL interface detected"),
    ],
}


class APIDocsScanner(BaseScanner):
    async def scan(self) -> FindingCollection:
        for path in API_DOC_PATHS:
            try:
                test_url = self.normalize_url(path)
                status, headers, body, cookies = await self.http_client.check_url(test_url, timeout=15)

                if status == 200 and body:
                    self._analyze_content(body, test_url)

            except Exception as e:
                logger.debug(f"Error scanning API doc path {path} on {self.target}: {e}")

        return self.findings

    def _analyze_content(self, body: str, url: str) -> None:
        for category, patterns in API_INDICATORS.items():
            for pattern, description in patterns:
                if re.search(pattern, body, re.I):
                    severity = "High" if category in ("swagger-json",) else "Medium"
                    evidence = self._extract_evidence(body, pattern)

                    title = f"API documentation exposed: {description} at {url}"
                    if category == "graphql" and "playground" in url.lower():
                        title = f"GraphQL Playground exposed: {url}"
                    elif category == "graphiql":
                        title = f"GraphiQL IDE exposed: {url}"
                    elif category == "swagger-ui":
                        title = f"Swagger UI exposed: {url}"

                    finding = create_finding(
                        target=self.target,
                        module="api_docs",
                        title=title,
                        evidence=evidence,
                        url=url,
                        status_code=200,
                        tags=["api", "api-docs", category.replace("_", "-")],
                    )
                    self.findings.add(finding)
                    return

        swagger_data = re.search(r'\{.*"(?:swagger|openapi)"\s*:\s*"[^"]+".*\}', body, re.DOTALL)
        if swagger_data:
            finding = create_finding(
                target=self.target,
                module="api_docs",
                title=f"API specification document exposed: {url}",
                evidence=swagger_data.group(0)[:500],
                url=url,
                status_code=200,
                tags=["api", "api-docs", "swagger-json"],
            )
            self.findings.add(finding)

    def _extract_evidence(self, body: str, pattern: str) -> str:
        lines = body.split("\n")
        matched_lines = []
        for i, line in enumerate(lines):
            if re.search(pattern, line, re.I):
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                snippet = "\n".join(lines[start:end])
                matched_lines.append(snippet)
                if len(matched_lines) >= 3:
                    break
        if matched_lines:
            return "\n...\n".join(matched_lines)[:1000]
        return body[:500]
