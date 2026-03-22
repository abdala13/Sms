import json
import shlex
from urllib.parse import parse_qsl, urlparse


class CurlParseError(ValueError):
    pass


class CurlParserService:
    DATA_FLAGS = {'--data', '--data-raw', '--data-binary', '-d', '--form', '--data-urlencode'}

    @staticmethod
    def _append_data(existing: str | None, new_value: str) -> str:
        if not existing:
            return new_value
        if '&' in existing or '&' in new_value:
            return f'{existing}&{new_value}'
        return new_value

    @staticmethod
    def parse(curl_command: str) -> dict:
        text = curl_command.strip()
        if not text.startswith('curl'):
            raise CurlParseError('Input must start with curl')
        try:
            parts = shlex.split(text)
        except ValueError as exc:
            raise CurlParseError(f'Unable to parse cURL: {exc}') from exc

        method = 'GET'
        url = None
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        data = None
        force_get = False
        i = 1
        while i < len(parts):
            part = parts[i]
            if part in {'-X', '--request'} and i + 1 < len(parts):
                method = parts[i + 1].upper()
                i += 2
                continue
            if part in {'-H', '--header'} and i + 1 < len(parts):
                header = parts[i + 1]
                if ':' in header:
                    key, value = header.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    headers[key] = value
                    if key.lower() == 'cookie':
                        for item in value.split(';'):
                            if '=' in item:
                                k, v = item.split('=', 1)
                                cookies[k.strip()] = v.strip()
                i += 2
                continue
            if part in {'-b', '--cookie'} and i + 1 < len(parts):
                raw = parts[i + 1]
                for item in raw.split(';'):
                    if '=' in item:
                        k, v = item.split('=', 1)
                        cookies[k.strip()] = v.strip()
                i += 2
                continue
            if part in CurlParserService.DATA_FLAGS and i + 1 < len(parts):
                data = CurlParserService._append_data(data, parts[i + 1])
                if method == 'GET' and not force_get:
                    method = 'POST'
                i += 2
                continue
            if part == '-G':
                force_get = True
                method = 'GET'
                i += 1
                continue
            if part.startswith('http://') or part.startswith('https://'):
                url = part
            i += 1

        if not url:
            raise CurlParseError('No URL found in cURL')

        parsed = urlparse(url)
        params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}"
        json_body = None
        form_body = None
        raw_body = None

        content_type = headers.get('Content-Type') or headers.get('content-type')
        if data:
            body_text = data.strip()
            if force_get:
                params.update(dict(parse_qsl(body_text, keep_blank_values=True)))
                data = None
            else:
                try:
                    json_body = json.loads(body_text)
                except Exception:
                    if content_type and 'json' in content_type.lower():
                        raw_body = body_text
                    elif '=' in body_text:
                        form_body = dict(parse_qsl(body_text, keep_blank_values=True))
                    else:
                        raw_body = body_text

        return {
            'method': method,
            'url': clean_url,
            'headers': headers,
            'cookies': cookies,
            'query_params': params,
            'json_body': json_body,
            'form_body': form_body,
            'raw_body': raw_body,
            'content_type': content_type,
        }
