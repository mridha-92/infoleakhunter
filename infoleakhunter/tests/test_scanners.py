import pytest

from infoleakhunter.config import DEFAULT_CONFIG
from infoleakhunter.models.finding import Severity
from infoleakhunter.scanner.secrets import SecretScanner
from infoleakhunter.scanner.directory_listing import DirectoryListingScanner
from infoleakhunter.scanner.source_code import SourceCodeScanner


class MockResponse:
    def __init__(self, status=200, headers=None, body="", cookies=None):
        self.status = status
        self._headers = headers or {}
        self._body = body
        self._cookies = cookies or {}

    @property
    def headers(self):
        return self._headers

    async def text(self):
        return self._body

    def __await__(self):
        return self._async_yield()

    async def _async_yield(self):
        return self


class MockHTTPClient:
    def __init__(self):
        self.responses = {}
        self.default_response = MockResponse(404, {}, "")

    def set_response(self, url_pattern, response):
        self.responses[url_pattern] = response

    async def check_url(self, url, timeout=None):
        for pattern, resp in self.responses.items():
            if pattern in url:
                return resp.status, resp.headers, resp._body, resp._cookies
        return self.default_response.status, {}, "", {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass

    async def get(self, url, headers=None, timeout=None):
        resp = MockResponse(200, {}, "")
        return resp

    async def request(self, method, url, **kwargs):
        return await self.get(url)

    async def head(self, url, headers=None):
        return MockResponse(200, {}, "")


class TestSecretScanner:
    @pytest.mark.asyncio
    async def test_detect_aws_key(self):
        config = dict(DEFAULT_CONFIG)
        config["secrets"]["entropy_enabled"] = False
        client = MockHTTPClient()
        client.set_response("example.com", MockResponse(200, {},
            "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nSECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"))
        scanner = SecretScanner("https://example.com", client, config)
        findings = await scanner.scan()
        assert findings.total() > 0
        titles = [f.title for f in findings.all()]
        assert any("AWS Access Key" in t for t in titles)

    @pytest.mark.asyncio
    async def test_detect_jwt(self):
        config = dict(DEFAULT_CONFIG)
        config["secrets"]["entropy_enabled"] = False
        client = MockHTTPClient()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNrvP5bGGunC4ojjK8oG4P1uDVhF7UdNQqFz0aA"
        client.set_response("example.com", MockResponse(200, {}, f"token={jwt}"))
        scanner = SecretScanner("https://example.com", client, config)
        findings = await scanner.scan()
        titles = [f.title for f in findings.all()]
        assert any("JWT" in t for t in titles)

    @pytest.mark.asyncio
    async def test_no_false_positive_on_benign(self):
        config = dict(DEFAULT_CONFIG)
        client = MockHTTPClient()
        client.set_response("example.com", MockResponse(200, {}, "<html><body>Hello World</body></html>"))
        scanner = SecretScanner("https://example.com", client, config)
        findings = await scanner.scan()
        assert findings.total() == 0


class TestDirectoryListingScanner:
    @pytest.mark.asyncio
    async def test_detect_apache_listing(self):
        config = dict(DEFAULT_CONFIG)
        client = MockHTTPClient()
        listing_body = """<html><head><title>Index of /</title></head>
<body><h1>Index of /</h1><table><tr><th>File</th></tr>
<tr><td><a href="backup/">backup/</a></td></tr>
<tr><td><a href="config/">config/</a></td></tr>
<tr><td><a href="secret.txt">secret.txt</a></td></tr>
</table></body></html>"""
        client.set_response("example.com/", MockResponse(200, {}, listing_body))
        scanner = DirectoryListingScanner("https://example.com", client, config)
        findings = await scanner.scan()
        titles = [f.title for f in findings.all()]
        assert any("directory listing" in t.lower() for t in titles)


class TestSourceCodeScanner:
    @pytest.mark.asyncio
    async def test_detect_todo_comment(self):
        config = dict(DEFAULT_CONFIG)
        client = MockHTTPClient()
        body = """<html><body>
        <!-- TODO: Remove this debug endpoint before production -->
        <p>Welcome</p>
        </body></html>"""
        client.set_response("example.com", MockResponse(200, {}, body))
        scanner = SourceCodeScanner("https://example.com", client, config)
        findings = await scanner.scan()
        titles = [f.title for f in findings.all()]
        assert any("TODO" in t or "FIXME" in t for t in titles)

    @pytest.mark.asyncio
    async def test_detect_email(self):
        config = dict(DEFAULT_CONFIG)
        client = MockHTTPClient()
        body = """<html><body>
        <p>Contact: developer@example.org</p>
        </body></html>"""
        client.set_response("example.com", MockResponse(200, {}, body))
        scanner = SourceCodeScanner("https://example.com", client, config)
        findings = await scanner.scan()
        titles = [f.title for f in findings.all()]
        assert any("email" in t.lower() for t in titles)
