"""Which network address a request came from, for rate limiting and abuse attribution.

``X-Forwarded-For`` is only meaningful when a proxy you control appends to it. With
``trusted_proxy_hops`` = N, the Nth entry from the end is the address the outermost trusted
proxy saw; everything before it was supplied by the client and is ignored. With 0 the header is
ignored and the socket peer is used. Entries that are not IP addresses are never trusted.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable


def client_address(
    forwarded_for: Iterable[str], peer: str | None, trusted_proxy_hops: int
) -> str | None:
    """The caller's address as a normalized IP string, or None when it cannot be determined.

    ``forwarded_for`` holds every X-Forwarded-For header value in arrival order.
    """
    if trusted_proxy_hops > 0:
        entries = [e.strip() for value in forwarded_for for e in value.split(",")]
        entries = [e for e in entries if e]
        if len(entries) >= trusted_proxy_hops:
            candidate = _normalize(entries[-trusted_proxy_hops])
            if candidate:
                return candidate
    return _normalize(peer) if peer else None


def forwardable(address: str | None) -> bool:
    """Whether ``address`` may be passed on to the Sporfie API as the caller's address.

    Only globally routable addresses qualify. Private, loopback, link-local and shared ranges
    are never forwarded: they identify no caller, and upstream proxies treat them as internal.
    """
    if not address:
        return False
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def rate_limit_key(address: str | None) -> str:
    """Bucket key for an address: IPv4 as is, IPv6 by /64 (one subscriber's usual allocation)."""
    if not address:
        return "unknown"
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address
    if ip.version == 6:
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)


def _normalize(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None
