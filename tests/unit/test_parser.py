from app.services.curl_parser import CurlParserService


def test_parse_simple_curl():
    data = CurlParserService.parse("curl https://example.com -H 'Accept: application/json'")
    assert data['method'] == 'GET'
    assert data['url'] == 'https://example.com'
    assert data['headers']['Accept'] == 'application/json'


def test_parse_cookie_header_and_json_body():
    data = CurlParserService.parse("curl 'https://example.com/api?x=1' -H 'Content-Type: application/json' -H 'Cookie: a=1; b=2' --data '{\"ok\":true}'")
    assert data['cookies'] == {'a': '1', 'b': '2'}
    assert data['json_body'] == {'ok': True}
    assert data['query_params']['x'] == '1'


def test_parse_g_mode_turns_data_into_params():
    data = CurlParserService.parse("curl -G https://example.com/search --data 'q=test&page=2'")
    assert data['method'] == 'GET'
    assert data['query_params'] == {'q': 'test', 'page': '2'}
    assert data['form_body'] is None
