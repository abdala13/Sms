from app.services.curl_parser import CurlParserService


def test_parse_simple_curl():
    data = CurlParserService.parse("curl https://example.com -H 'Accept: application/json'")
    assert data['method'] == 'GET'
    assert data['url'] == 'https://example.com'
    assert data['headers']['Accept'] == 'application/json'
