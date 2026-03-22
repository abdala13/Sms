import httpx
from app.services.failure_policy import classify_error


def test_timeout_classification():
    assert classify_error(httpx.ReadTimeout('x'), None) == 'network.timeout'


def test_http_429_classification():
    assert classify_error(None, 429) == 'http.429'
