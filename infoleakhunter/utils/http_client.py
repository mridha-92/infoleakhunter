from __future__ import annotations

import asyncio
import logging
import random
import ssl
from typing import Any

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from infoleakhunter.exceptions import HTTPError, RateLimitError, TimeoutError

logger = logging.getLogger("infoleakhunter.http")


class HTTPClient:
    def __init__(
        self,
        config: dict[str, Any],
        user_agents: list[str] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.config = config
        self._user_agents = user_agents or config.get("http", {}).get("user_agents", [])
        self._extra_headers = extra_headers or config.get("http", {}).get("headers", {})
        self._timeout = ClientTimeout(total=config.get("scan", {}).get("timeout", 30))
        self._verify_ssl = config.get("scan", {}).get("verify_ssl", True)
        self._follow_redirects = config.get("scan", {}).get("follow_redirects", True)
        self._max_redirects = config.get("scan", {}).get("max_redirects", 10)
        self._rate_limit = config.get("scan", {}).get("rate_limit", 50)
        self._semaphore: asyncio.Semaphore | None = None
        self._session: aiohttp.ClientSession | None = None
        self._rate_limiter: asyncio.Semaphore | None = None
        self._retries = config.get("scan", {}).get("max_retries", 3)
        self._retry_delay = config.get("scan", {}).get("retry_delay", 1.0)
        self._current_agent_index = 0

    def _get_user_agent(self) -> str:
        if not self._user_agents:
            return "InfoLeakHunter/1.0"
        if self.config.get("scan", {}).get("user_agent_rotation", True):
            self._current_agent_index = (self._current_agent_index + 1) % len(self._user_agents)
            return self._user_agents[self._current_agent_index]
        return self._user_agents[0]

    async def __aenter__(self) -> HTTPClient:
        ssl_context = None
        if not self._verify_ssl:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        connector = TCPConnector(
            ssl=ssl_context,
            limit=self.config.get("scan", {}).get("concurrent_requests", 100),
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )

        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self._timeout,
        )
        self._semaphore = asyncio.Semaphore(self._rate_limit)
        self._rate_limiter = asyncio.Semaphore(self._rate_limit)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    async def request(
        self,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        allow_redirects: bool | None = None,
        timeout: int | None = None,
        data: Any = None,
        cookies: dict[str, str] | None = None,
    ) -> aiohttp.ClientResponse:
        if not self._session:
            raise RuntimeError("HTTPClient not initialized. Use 'async with' context manager.")

        async with self._rate_limiter:
            for attempt in range(self._retries + 1):
                try:
                    req_headers = dict(self._extra_headers)
                    req_headers["User-Agent"] = self._get_user_agent()
                    if headers:
                        req_headers.update(headers)

                    redirect_setting = allow_redirects if allow_redirects is not None else self._follow_redirects

                    async with self._semaphore:
                        async with self._session.request(
                            method=method,
                            url=url,
                            headers=req_headers,
                            allow_redirects=redirect_setting,
                            max_redirects=self._max_redirects,
                            timeout=ClientTimeout(total=timeout or self._timeout.total),
                            data=data,
                            cookies=cookies,
                        ) as response:
                            await response.read()
                            return response

                except asyncio.TimeoutError:
                    logger.debug(f"Timeout on {url} (attempt {attempt + 1})")
                    if attempt < self._retries:
                        await asyncio.sleep(self._retry_delay * (attempt + 1))
                    else:
                        raise TimeoutError(f"Request timed out: {url}")

                except aiohttp.ClientResponseError as e:
                    if e.status == 429:
                        retry_after = int(e.headers.get("Retry-After", 5)) if e.headers else 5
                        await asyncio.sleep(retry_after)
                        if attempt >= self._retries:
                            raise RateLimitError(f"Rate limited on {url}")

                    elif 500 <= e.status < 600 and attempt < self._retries:
                        await asyncio.sleep(self._retry_delay * (attempt + 1))

                    else:
                        raise HTTPError(f"HTTP {e.status}: {url}", status_code=e.status, url=url)

                except aiohttp.ClientError as e:
                    if attempt < self._retries:
                        await asyncio.sleep(self._retry_delay * (attempt + 1))
                    else:
                        raise HTTPError(f"Request failed: {url} - {e}", url=url)

            raise HTTPError(f"Max retries exceeded: {url}", url=url)

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
    ) -> aiohttp.ClientResponse:
        return await self.request(url, "GET", headers=headers, timeout=timeout)

    async def head(
        self,
        url: str,
        headers: dict[str, str] | None = None,
    ) -> aiohttp.ClientResponse:
        return await self.request(url, "HEAD", headers=headers, allow_redirects=False)

    async def check_url(self, url: str, timeout: int | None = 10) -> tuple[int, dict[str, str], str, dict[str, str]]:
        try:
            resp = await self.get(url, timeout=timeout)
            headers = dict(resp.headers)
            body = await resp.text() if resp.content else ""
            cookies = {k: v.value for k, v in resp.cookies.items()}
            return resp.status, headers, body, cookies
        except HTTPError:
            return 0, {}, "", {}
        except Exception:
            return 0, {}, "", {}

    async def check_url_binary(self, url: str, timeout: int | None = 10) -> tuple[int, dict[str, str], bytes, dict[str, str]]:
        try:
            resp = await self.get(url, timeout=timeout)
            headers = dict(resp.headers)
            body = await resp.read() if resp.content else b""
            cookies = {k: v.value for k, v in resp.cookies.items()}
            return resp.status, headers, body, cookies
        except HTTPError:
            return 0, {}, b"", {}
        except Exception:
            return 0, {}, b"", {}
