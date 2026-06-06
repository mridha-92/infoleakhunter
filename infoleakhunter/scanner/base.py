from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from infoleakhunter.models.finding import FindingCollection
from infoleakhunter.utils.http_client import HTTPClient

logger = logging.getLogger("infoleakhunter.scanner")


class BaseScanner(ABC):
    def __init__(self, target: str, http_client: HTTPClient, config: dict[str, Any]) -> None:
        self.target = target.rstrip("/")
        self.http_client = http_client
        self.config = config
        self.findings = FindingCollection()

    @abstractmethod
    async def scan(self) -> FindingCollection:
        pass

    def normalize_url(self, path: str) -> str:
        path = path.lstrip("/")
        return f"{self.target}/{path}"

    def normalize_subdomain(self, subdomain: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        netloc = parsed.netloc or self.target
        return f"{parsed.scheme}://{subdomain}.{netloc}"
