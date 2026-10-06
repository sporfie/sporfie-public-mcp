"""Sporfie Public API MCP server tests.

No network: the HTTP layer is exercised through ``httpx.MockTransport``
injected into ``SporfieApiClient``, and the tool layer through a stub ctx
(``SimpleNamespace`` mirroring ``ctx.request_context.request``) plus a
module-level ``_CLIENT`` swap.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import Route as StarRoute
from starlette.testclient import TestClient

import sporfie_public_server.server as srv
from sporfie_public_server.client import SporfieApiClient, SporfieApiError, SporfieApiHttpError
from sporfie_public_server.help_center import HelpCenterClient, strip_html
from sporfie_public_server.rate_limit import RateLimitMiddleware

BEARER = "Bearer test-token-123"


def ctx_with(
    headers: dict[str, str] | list[tuple[str, str]] | None, client_host: str | None = None
) -> SimpleNamespace:
    """A stub tool context. Pass a list of pairs to send a header more than once."""
    request = None
    if headers is not None:
        client = SimpleNamespace(host=client_host) if client_host else None
        if isinstance(headers, dict):
            parsed = Headers(headers)
        else:
            parsed = Headers(raw=[(k.lower().encode(), v.encode()) for k, v in headers])
        request = SimpleNamespace(headers=parsed, client=client)
    return SimpleNamespace(request_context=SimpleNamespace(request=request))


def mock_client(handler, max_chars: int = 20000) -> SporfieApiClient:
    return SporfieApiClient(
        base_url="http://backend.test",
        timeout_s=5,
        max_response_chars=max_chars,
        transport=httpx.MockTransport(handler),
    )


# ----- _authorization extraction -----


def test_authorization_present() -> None:
    assert srv._authorization(ctx_with({"authorization": BEARER})) == BEARER


def test_authorization_absent_header() -> None:
    assert srv._authorization(ctx_with({})) is None


def test_authorization_no_request() -> None:
    assert srv._authorization(ctx_with(None)) is None


def test_authorization_outside_request_context() -> None:
    class _Raising:
        @property
        def request_context(self):
            raise ValueError("outside request")

    assert srv._authorization(_Raising()) is None


@pytest.mark.parametrize(
    "value", ["Bearer tok", "bearer tok", "BEARER tok", "BeArEr   tok", "  Bearer tok  "]
)
def test_authorization_scheme_is_case_insensitive_and_forwarded_canonically(value) -> None:
    assert srv._authorization(ctx_with({"authorization": value})) == "Bearer tok"


@pytest.mark.parametrize("value", ["", "   "])
def test_authorization_empty_header_counts_as_absent(value) -> None:
    assert srv._authorization(ctx_with({"authorization": value})) is None


@pytest.mark.parametrize(
    "first,second",
    [("Bearer a", "Bearer b"), ("Bearer a", "Bearer a"), ("Bearer a", ""), ("", "Bearer b")],
)
def test_authorization_more_than_one_header_is_rejected(first, second) -> None:
    ctx = ctx_with([("Authorization", first), ("Authorization", second)])
    with pytest.raises(ToolError, match="exactly one Authorization header"):
        srv._authorization(ctx)


@pytest.mark.parametrize(
    "value",
    ["Basic dXNlcjpwYXNz", "Token abc", "Bearer", "Bearer a b", "Bearertok", "abc.def.ghi"],
)
def test_authorization_that_is_not_a_bearer_credential_is_rejected(value) -> None:
    with pytest.raises(ToolError, match="not a Bearer credential"):
        srv._authorization(ctx_with({"authorization": value}))


# ----- client behavior -----


async def test_client_forwards_auth_and_params() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["Authorization"]
        seen["ua"] = request.headers["User-Agent"]
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"ok": True})

    client = mock_client(handler)
    out = await client.request(
        "GET",
        "/public/event-search-by-company",
        BEARER,
        params={"companyKey": "c1", "state": "current", "page": 0, "empty": None},
    )
    assert seen["auth"] == BEARER
    assert seen["ua"].startswith("sporfie-public-mcp/")
    assert "companyKey=c1" in seen["url"] and "empty" not in seen["url"]
    assert json.loads(out) == {"ok": True}


async def test_client_error_status_carries_backend_body() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_bearer"})

    with pytest.raises(SporfieApiHttpError) as err:
        await mock_client(handler).request("GET", "/public/events/e1", BEARER)
    assert err.value.status == 401
    assert str(err.value).startswith("HTTP 401:") and "invalid_bearer" in str(err.value)


async def test_client_truncates_large_bodies() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"blob": "x" * 5000})

    out = await mock_client(handler, max_chars=100).request("GET", "/public/events/e1", BEARER)
    assert len(out) < 300 and "truncated" in out


async def test_client_transport_failure_raises() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    with pytest.raises(SporfieApiError):
        await mock_client(handler).request("GET", "/public/events/e1", BEARER)


# ----- tool layer -----


async def test_tool_without_auth_is_an_error_with_instructions() -> None:
    with pytest.raises(ToolError) as err:
        await srv.get_event("evt1", ctx_with({}))
    assert "Authorization" in str(err.value) and "api token" in str(err.value).lower()


async def test_tool_happy_path_hits_expected_route(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.path
        seen["auth"] = request.headers["Authorization"]
        return httpx.Response(200, json={"eventKey": "e1", "name": "match"})

    monkeypatch.setattr(srv, "_CLIENT", mock_client(handler))
    out = await srv.get_event("ext-42", ctx_with({"authorization": BEARER}))
    assert seen == {"method": "GET", "path": "/public/events/ext-42", "auth": BEARER}
    assert "eventKey" in out


async def test_tool_forwards_the_credential_in_canonical_bearer_form(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["Authorization"])
        return httpx.Response(200, json={"eventKey": "e1"})

    monkeypatch.setattr(srv, "_CLIENT", mock_client(handler))
    await srv.get_event("e1", ctx_with({"authorization": "BEARER   tok-1"}))
    assert seen == ["Bearer tok-1"]  # the API strips a case-sensitive "Bearer "


@pytest.mark.parametrize(
    "headers",
    [
        [("Authorization", "Bearer a"), ("Authorization", "Bearer b")],
        [("Authorization", "Basic dXNlcjpwYXNz")],
    ],
)
async def test_tool_sends_nothing_for_an_ambiguous_or_non_bearer_header(
    monkeypatch: pytest.MonkeyPatch, headers
) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={})

    monkeypatch.setattr(srv, "_CLIENT", mock_client(handler))
    with pytest.raises(ToolError, match="Authorization"):
        await srv.get_event("e1", ctx_with(headers))
    assert calls == []


async def test_search_events_rejects_bad_state() -> None:
    with pytest.raises(ToolError, match="future, current, past"):
        await srv.search_events("c1", ctx_with({"authorization": BEARER}), state="running")


async def test_create_event_posts_body(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(201, json={"eventKey": "eNew"})

    monkeypatch.setattr(srv, "_CLIENT", mock_client(handler))
    event = {"companyKey": "c1", "name": "U19 final", "sport": "football"}
    out = await srv.create_event("myid-1", event, ctx_with({"authorization": BEARER}))
    assert seen["path"] == "/public/events/myid-1" and seen["body"] == event
    assert "eNew" in out


async def test_transport_failure_becomes_clean_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    monkeypatch.setattr(srv, "_CLIENT", mock_client(handler))
    with pytest.raises(ToolError) as err:
        await srv.list_sports(ctx_with({"authorization": BEARER}))
    assert str(err.value) == "Sporfie API unreachable: could not connect"


# ----- Help Center (anonymous) -----


def hc_client(handler, max_chars: int = 20000) -> HelpCenterClient:
    return HelpCenterClient(
        base_url="https://hc.test",
        timeout_s=5,
        max_response_chars=max_chars,
        transport=httpx.MockTransport(handler),
    )


def test_strip_html() -> None:
    html = "<h1>Title</h1><p>Line <em>one</em>.</p><script>evil()</script><li>two</li>"
    text = strip_html(html)
    assert "Title" in text and "Line one." in text and "two" in text
    assert "evil" not in text


async def test_hc_search_renders_results_without_auth() -> None:
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["auth"] = request.headers.get("Authorization")
        return httpx.Response(
            200,
            json={
                "count": 1,
                "page": 1,
                "page_count": 1,
                "results": [
                    {
                        "id": 42,
                        "title": "Camera setup",
                        "snippet": "connect the <em>camera</em>",
                        "html_url": "https://hc.test/hc/en-us/articles/42",
                    }
                ],
            },
        )

    out = await hc_client(handler).search("camera", "en-us", 1)
    assert seen["path"] == "/api/v2/help_center/articles/search.json"
    assert seen["auth"] is None  # anonymous by design
    assert "[42] Camera setup" in out and "connect the camera" in out


async def test_hc_article_strips_and_truncates() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "article": {
                    "title": "Long article",
                    "body": "<p>" + "word " * 500 + "</p>",
                    "html_url": "https://hc.test/hc/en-us/articles/7",
                }
            },
        )

    out = await hc_client(handler, max_chars=200).article(7, "en-us")
    assert out.startswith("# Long article")
    assert "truncated" in out and "https://hc.test/hc/en-us/articles/7" in out


async def test_hc_sections_grouped_by_category() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "categories" in request.url.path:
            return httpx.Response(200, json={"categories": [{"id": 1, "name": "FAQ"}]})
        return httpx.Response(
            200, json={"sections": [{"id": 10, "name": "Cameras", "category_id": 1}]}
        )

    out = await hc_client(handler).sections("en-us")
    assert "[10] FAQ / Cameras" in out


async def test_hc_tool_transport_failure_is_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    monkeypatch.setattr(srv, "_HC", hc_client(handler))
    with pytest.raises(ToolError, match="^Help Center unreachable"):
        await srv.search_help_center("camera")


# ----- rate limiting -----


def limited_app(limit: int, trusted_proxy_hops: int = 1) -> TestClient:
    async def ok(_: object) -> JSONResponse:
        return JSONResponse({"ok": True})

    app = Starlette(routes=[StarRoute("/mcp", ok, methods=["GET"]), StarRoute("/health", ok)])
    app.add_middleware(
        RateLimitMiddleware, limit_per_minute=limit, trusted_proxy_hops=trusted_proxy_hops
    )
    return TestClient(app)


def test_rate_limit_allows_then_blocks() -> None:
    client = limited_app(3)
    for _ in range(3):
        assert client.get("/mcp").status_code == 200
    blocked = client.get("/mcp")
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "60"
    assert "rate_limited" in blocked.text


def test_rate_limit_health_exempt() -> None:
    client = limited_app(1)
    for _ in range(5):
        assert client.get("/health").status_code == 200


def test_rate_limit_uses_last_forwarded_for_entry() -> None:
    client = limited_app(1)
    # Same connecting address (last XFF entry) with varying spoofed prefixes
    # must share one bucket — the spoofable first entry is ignored.
    assert client.get("/mcp", headers={"X-Forwarded-For": "1.1.1.1, 9.9.9.9"}).status_code == 200
    assert client.get("/mcp", headers={"X-Forwarded-For": "2.2.2.2, 9.9.9.9"}).status_code == 429
    # A different connecting address gets its own bucket.
    assert client.get("/mcp", headers={"X-Forwarded-For": "8.8.8.8"}).status_code == 200


def test_rate_limit_disabled_with_zero() -> None:
    client = limited_app(0)
    for _ in range(10):
        assert client.get("/mcp").status_code == 200


# ----- ASGI wiring -----


def test_health_route_registered() -> None:
    paths = [getattr(r, "path", None) for r in srv.app.router.routes]
    assert "/health" in paths


def test_public_hostname_allowed_by_transport_security() -> None:
    security = srv.mcp.settings.transport_security
    assert security is not None and security.enable_dns_rebinding_protection
    assert "mcp.sporfie.com" in security.allowed_hosts
    assert "localhost:*" in security.allowed_hosts
