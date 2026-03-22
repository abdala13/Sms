import ipaddress
import socket
from urllib.parse import urlparse
from app.core.config import get_settings


class PolicyViolation(ValueError):
    pass


def validate_target_url(url: str) -> None:
    parsed = urlparse(url)
    schemes = set(get_settings().allowed_schemes.split(','))
    if parsed.scheme not in schemes:
        raise PolicyViolation('Unsupported scheme')
    if not parsed.hostname:
        raise PolicyViolation('Missing host')
    if parsed.hostname in {'localhost', '127.0.0.1'}:
        raise PolicyViolation('Localhost is blocked')
    if get_settings().block_private_networks:
        try:
            infos = socket.getaddrinfo(parsed.hostname, None)
            for info in infos:
                ip = ipaddress.ip_address(info[4][0])
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    raise PolicyViolation('Private/internal targets are blocked')
        except socket.gaierror:
            return
