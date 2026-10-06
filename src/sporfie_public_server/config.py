"""Environment-driven configuration for the Sporfie Public API MCP server."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    """Runtime configuration, loaded once at import time.

    base_url (SPORFIE_API_BASE_URL): origin of the Sporfie API. The default is the public API,
        so a local run works out of the box.
    timeout_s (SPORFIE_API_TIMEOUT_S): HTTP timeout toward the API, applied to each phase
        (connect, write, read) rather than to the request as a whole.
    deadline_s (SPORFIE_API_DEADLINE_S): total time one upstream request may take, from the
        first byte sent to the last byte read, however slowly the upstream trickles. Raised to
        timeout_s if set lower, since a per-phase timeout alone bounds nothing.
    max_request_bytes (SPORFIE_MCP_MAX_REQUEST_BYTES): largest request body accepted; a bigger
        one is answered with 413 before it is parsed. The body of every call in flight is held in
        memory, so this, times the calls admitted at once, is what bounds the memory a flood of
        requests can pin. Tool arguments are small JSON: the default is 256 KiB, against the
        4 MiB of the MCP SDK.
    max_response_chars (SPORFIE_API_MAX_RESPONSE_CHARS): response text handed to the model is
        truncated to this many characters, so a long list cannot flood an agent's context.
    max_response_bytes (SPORFIE_API_MAX_RESPONSE_BYTES): at most this many bytes of an upstream
        response are read; the rest is never downloaded. Compressed responses are refused
        outright, so this bounds memory as well as transfer.
    max_concurrent_upstream (SPORFIE_MCP_MAX_CONCURRENT_UPSTREAM): upstream requests in flight
        per client (API and Help Center each); further calls wait for a free slot.
    max_queued_upstream (SPORFIE_MCP_MAX_QUEUED_UPSTREAM): calls allowed to wait for a slot at
        once, per client. When that many already wait, the next call fails at once with "busy".
    queue_timeout_s (SPORFIE_MCP_QUEUE_TIMEOUT_S): longest a call waits for a free slot before it
        fails with "busy".
    help_center_base_url (ZENDESK_HELP_CENTER_BASE_URL): the anonymous Help Center API origin.
    rate_limit_per_minute (SPORFIE_MCP_RATE_LIMIT_PER_MINUTE): per-client-address backstop;
        0 disables it.
    trusted_proxy_hops (SPORFIE_MCP_TRUSTED_PROXY_HOPS): how many proxies in front of this
        server append to X-Forwarded-For. The default, 0, ignores the header and uses the
        socket peer; set 1 behind a single load balancer. Never set it higher than the real
        number of proxies, or clients can choose the address they are limited under.
    allowed_hosts (SPORFIE_MCP_ALLOWED_HOSTS): Host headers the transport accepts
        (DNS-rebinding protection).
    oauth_issuer (SPORFIE_MCP_OAUTH_ISSUER): OAuth authorization server; empty turns OAuth off.
    public_url (SPORFIE_MCP_PUBLIC_URL): this server's public origin.
    """

    base_url: str
    timeout_s: float
    deadline_s: float
    max_request_bytes: int
    max_response_chars: int
    max_response_bytes: int
    max_concurrent_upstream: int
    max_queued_upstream: int
    queue_timeout_s: float
    help_center_base_url: str
    rate_limit_per_minute: int
    trusted_proxy_hops: int
    allowed_hosts: tuple[str, ...]
    oauth_issuer: str
    public_url: str


def load_config() -> Config:
    timeout_s = float(os.environ.get("SPORFIE_API_TIMEOUT_S", "30"))
    return Config(
        base_url=os.environ.get("SPORFIE_API_BASE_URL", "https://www.sporfie.com").rstrip("/"),
        timeout_s=timeout_s,
        deadline_s=max(float(os.environ.get("SPORFIE_API_DEADLINE_S", "45")), timeout_s),
        max_request_bytes=int(os.environ.get("SPORFIE_MCP_MAX_REQUEST_BYTES", str(256 * 1024))),
        max_response_chars=int(os.environ.get("SPORFIE_API_MAX_RESPONSE_CHARS", "20000")),
        max_response_bytes=int(
            os.environ.get("SPORFIE_API_MAX_RESPONSE_BYTES", str(2 * 1024 * 1024))
        ),
        max_concurrent_upstream=int(os.environ.get("SPORFIE_MCP_MAX_CONCURRENT_UPSTREAM", "32")),
        max_queued_upstream=int(os.environ.get("SPORFIE_MCP_MAX_QUEUED_UPSTREAM", "64")),
        queue_timeout_s=float(os.environ.get("SPORFIE_MCP_QUEUE_TIMEOUT_S", "5")),
        # Zendesk Help Center: published articles are anonymously readable, so the help tools
        # need no credential (see help_center.py).
        help_center_base_url=os.environ.get(
            "ZENDESK_HELP_CENTER_BASE_URL", "https://sporfie.zendesk.com"
        ).rstrip("/"),
        rate_limit_per_minute=int(os.environ.get("SPORFIE_MCP_RATE_LIMIT_PER_MINUTE", "120")),
        trusted_proxy_hops=int(os.environ.get("SPORFIE_MCP_TRUSTED_PROXY_HOPS", "0")),
        # Without the public hostname here, requests arriving through it are rejected with
        # "Invalid Host header" (421). ":*" = any port.
        allowed_hosts=tuple(
            h.strip()
            for h in os.environ.get(
                "SPORFIE_MCP_ALLOWED_HOSTS", "mcp.sporfie.com,localhost:*,127.0.0.1:*"
            ).split(",")
            if h.strip()
        ),
        # OAuth 2.1: the authorization server this resource server points clients at (RFC 9728).
        # Empty turns OAuth off: no protected-resource metadata and no 401 challenge (the manual
        # bearer-header path works either way). Set it, e.g. https://api.sporfie.com, to enable
        # one-click connect.
        oauth_issuer=os.environ.get("SPORFIE_MCP_OAUTH_ISSUER", "").rstrip("/"),
        # This server's own public origin, used to build the resource identifier + metadata URL.
        public_url=os.environ.get("SPORFIE_MCP_PUBLIC_URL", "https://mcp.sporfie.com").rstrip("/"),
    )
