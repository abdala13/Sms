import httpx


def classify_error(exc: Exception | None, status_code: int | None) -> str | None:
    if status_code:
        if status_code == 429:
            return 'http.429'
        if 400 <= status_code < 500:
            return f'http.{status_code}'
        if 500 <= status_code < 600:
            return f'http.{status_code}'
    if isinstance(exc, httpx.TimeoutException):
        return 'network.timeout'
    if isinstance(exc, httpx.ConnectError):
        return 'network.connection'
    return 'unknown' if exc else None
