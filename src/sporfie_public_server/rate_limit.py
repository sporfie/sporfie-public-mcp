"""Per-client-address rate limiting for the public MCP endpoint.

A backstop, not the primary abuse control: a fixed 60-second window per client address, kept
in memory per process (with N replicas the effective ceiling is N times the configured limit).
It bounds how hard a single address can hammer the handshake or cycle through bearer tokens.

The client address comes from client_ip.py: behind ``trusted_proxy_hops`` proxies that append
to X-Forwarded-For, the entry that proxy appended; otherwise the socket peer. IPv6 addresses
share a bucket per /64. /health is exempt so load-balancer probes are never throttled.

Memory and time are bounded: at most ``max_tracked`` buckets are kept, least recently seen
first out, and every request does constant work.
"""

from __future__ import annotations

import time
from collections import OrderedDict

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .client_ip import client_address, rate_limit_key

_WINDOW_S = 60
_MAX_TRACKED = 10_000


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        limit_per_minute: int,
        exempt_paths: tuple[str, ...] = ("/health",),
        trusted_proxy_hops: int = 0,
        max_tracked: int = _MAX_TRACKED,
    ) -> None:
        self.app = app
        self.limit = limit_per_minute
        self.exempt_paths = exempt_paths
        self.trusted_proxy_hops = trusted_proxy_hops
        self.max_tracked = max_tracked
        self._windows: OrderedDict[str, tuple[float, int]] = OrderedDict()

    def _client_key(self, scope: Scope) -> str:
        forwarded = [
            value.decode("latin-1")
            for name, value in scope.get("headers", [])
            if name == b"x-forwarded-for"
        ]
        client = scope.get("client")
        peer = client[0] if client else None
        return rate_limit_key(client_address(forwarded, peer, self.trusted_proxy_hops))

    def _over_limit(self, key: str) -> bool:
        now = time.monotonic()
        start, count = self._windows.pop(key, (now, 0))
        if now - start >= _WINDOW_S:
            start, count = now, 0
        count += 1
        self._windows[key] = (start, count)  # re-insert: most recently seen goes last
        while len(self._windows) > self.max_tracked:
            self._windows.popitem(last=False)
        return count > self.limit

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or self.limit <= 0 or scope.get("path") in self.exempt_paths:
            await self.app(scope, receive, send)
            return
        if self._over_limit(self._client_key(scope)):
            response = JSONResponse(
                {
                    "error": "rate_limited",
                    "message": (
                        f"Too many requests from this address (limit {self.limit}/minute). "
                        "Slow down and retry."
                    ),
                },
                status_code=429,
                headers={"Retry-After": str(_WINDOW_S)},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)
