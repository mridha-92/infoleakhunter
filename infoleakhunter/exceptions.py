class InfoLeakHunterError(Exception):
    """Base exception for InfoLeakHunter."""

    pass


class ConfigurationError(InfoLeakHunterError):
    """Raised when configuration is invalid."""

    pass


class ScanError(InfoLeakHunterError):
    """Raised when a scan operation fails."""

    pass


class HTTPError(ScanError):
    """Raised on HTTP request failures."""

    def __init__(self, message: str, status_code: int | None = None, url: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.url = url


class RateLimitError(ScanError):
    """Raised when rate limited."""

    pass


class TimeoutError(ScanError):
    """Raised when a request times out."""

    pass


class InvalidTargetError(InfoLeakHunterError):
    """Raised when the target URL is invalid."""

    pass


class ReportError(InfoLeakHunterError):
    """Raised when report generation fails."""

    pass
