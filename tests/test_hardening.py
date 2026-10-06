"""Regression tests for the pre-publication security review (2026-09-29).

Every tool argument is untrusted input. These tests pin down that a tool can only reach its own
endpoint, that upstream responses are read under a byte cap, that failures are MCP tool errors
with sanitized text, that only the trusted client address is forwarded, and that the rate-limit
table stays bounded.
"""

from __future__ import annotations

import dataclasses
import importlib
import importlib.metadata
import json

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

import sporfie_public_server
import sporfie_public_server.server as srv
from sporfie_public_server import paths
from sporfie_public_server.client import SporfieApiClient, SporfieApiError, SporfieApiHttpError
from sporfie_public_server.client_ip import client_address, forwardable, rate_limit_key
from sporfie_public_server.config import load_config
from sporfie_public_server.help_center import HelpCenterClient
from sporfie_public_server.rate_limit import RateLimitMiddleware

from .test_server import BEARER, ctx_with

FIREBASE_KEY = "-MCka7Eq-SGcom52zt1f"

# Inputs that are not plain Sporfie keys: dot segments (raw and encoded), separators, URL
# delimiters, whitespace, non-ASCII, empty and over-long values.
NOT_A_KEY = [
    "",
    ".",
    "..",
    "../x",
    "..%2Fx",
    "%2e%2e",
    "a/b",
    "a\\b",
    "x?y=1",
    "x#",
    "x%23",
    "a b",
    "a.b",
    "é",
    "a\n",
    "a" * 129,
]


class Recorder:
    """MockTransport handler that records every request that would have left the process."""

    def __init__(self, response: httpx.Response | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self.response = response or httpx.Response(200, json={"ok": True})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.response


def api_client(handler, **kwargs) -> SporfieApiClient:
    return SporfieApiClient(
        base_url="http://backend.test",
        timeout_s=5,
        max_response_chars=kwargs.pop("max_chars", 20000),
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


def hc_client(handler, **kwargs) -> HelpCenterClient:
    return HelpCenterClient(
        base_url="https://hc.test",
        timeout_s=5,
        max_response_chars=20000,
        transport=httpx.MockTransport(handler),
        **kwargs,
    )


AUTHED = {"authorization": BEARER}

# (tool, call with a key, method, path template the tool must hit)
PATH_TOOLS = [
    ("get_event", lambda k, c: srv.get_event(k, c), "GET", "/public/events/{}"),
    (
        "create_event",
        lambda k, c: srv.create_event(k, {"companyKey": "c1"}, c),
        "POST",
        "/public/events/{}",
    ),
    (
        "update_event",
        lambda k, c: srv.update_event(k, {"name": "n"}, c),
        "PATCH",
        "/public/events/{}",
    ),
    ("close_event", lambda k, c: srv.close_event(k, c), "POST", "/public/events/{}/close"),
    ("delete_event", lambda k, c: srv.delete_event(k, c), "DELETE", "/public/events/{}"),
    (
        "get_active_event_key",
        lambda k, c: srv.get_active_event_key(k, c),
        "GET",
        "/public/places/{}/activeEventKey",
    ),
    (
        "register_click",
        lambda k, c: srv.register_click(k, 1_700_000_000_000, c),
        "POST",
        "/public/events/{}/clicks",
    ),
    ("get_moment", lambda k, c: srv.get_moment(k, c), "GET", "/public/moments/{}"),
    (
        "update_moment",
        lambda k, c: srv.update_moment(k, {"metadata": {}}, c),
        "PATCH",
        "/public/moments/{}",
    ),
    ("delete_moment", lambda k, c: srv.delete_moment(k, c), "DELETE", "/public/moments/{}"),
    (
        "watch_event",
        lambda k, c: srv.watch_event(k, "https://hooks.example/x", c),
        "PUT",
        "/public/events/{}/watch",
    ),
    ("unwatch_event", lambda k, c: srv.unwatch_event(k, c), "DELETE", "/public/events/{}/watch"),
]


# ----- a tool only ever reaches its own endpoint -----


@pytest.mark.parametrize("name,call,method,template", PATH_TOOLS, ids=[t[0] for t in PATH_TOOLS])
async def test_tool_hits_exactly_its_own_template(monkeypatch, name, call, method, template):
    recorder = Recorder()
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    await call(FIREBASE_KEY, ctx_with(AUTHED))
    (request,) = recorder.requests
    assert request.method == method
    assert request.url.raw_path.decode() == template.format(FIREBASE_KEY)
    assert paths.matches_template(request.url.path, template)


@pytest.mark.parametrize("name,call,method,template", PATH_TOOLS, ids=[t[0] for t in PATH_TOOLS])
@pytest.mark.parametrize("value", NOT_A_KEY)
async def test_tool_rejects_non_key_input_before_any_request(
    monkeypatch, name, call, method, template, value
):
    recorder = Recorder()
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    with pytest.raises(paths.InvalidArgument):
        await call(value, ctx_with(AUTHED))
    assert recorder.requests == []


@pytest.mark.parametrize(
    "path",
    [
        "/public/events/./x",
        "/public/events/../../x",
        "//other.example/x",
        "/public/events/x#f",
        "/public/events/x?q=1",
    ],
)
async def test_client_refuses_paths_httpx_would_rewrite(path):
    recorder = Recorder()
    with pytest.raises(SporfieApiError, match="Refusing"):
        await api_client(recorder).request("GET", path, BEARER)
    assert recorder.requests == []


def test_build_path_encodes_and_checks_shape():
    assert paths.build_path("/public/events/{}/watch", e=FIREBASE_KEY) == (
        f"/public/events/{FIREBASE_KEY}/watch"
    )
    with pytest.raises(ValueError):
        paths.build_path("/public/events/{}/{}", e="a")  # slot count mismatch is a bug
    assert not paths.matches_template("/public/events/a/b/watch", "/public/events/{}/watch")
    assert not paths.matches_template("/public/events/../watch", "/public/events/{}/watch")


async def test_help_center_locale_and_article_id_are_validated():
    recorder = Recorder(httpx.Response(200, json={"article": {"title": "t", "body": "b"}}))
    client = hc_client(recorder)
    for bad_locale in ["../../x", "en-us/../../x", "en-us#", "e", "english-language-x"]:
        with pytest.raises(paths.InvalidArgument):
            await client.article(1, bad_locale)
        with pytest.raises(paths.InvalidArgument):
            await client.sections(bad_locale)
        with pytest.raises(paths.InvalidArgument):
            await client.search("camera", bad_locale, 1)
    for bad_id in [0, -1, True]:
        with pytest.raises(paths.InvalidArgument):
            await client.article(bad_id, "en-us")
    assert recorder.requests == []
    await client.article(42, "EN-US")
    assert recorder.requests[0].url.path == "/api/v2/help_center/en-us/articles/42.json"


async def test_search_events_bounds_paging(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    for page_size, page in [(0, 0), (101, 0), (20, -1), (20, 10_001)]:
        with pytest.raises(paths.InvalidArgument):
            await srv.search_events("c1", ctx_with(AUTHED), page_size=page_size, page=page)
    assert recorder.requests == []
    await srv.search_events("c1", ctx_with(AUTHED), page_size=100, page=3)
    assert recorder.requests[0].url.params["pageSize"] == "100"


# ----- upstream responses are read under a byte cap -----


async def test_client_stops_reading_past_the_byte_cap():
    pulled = 0

    async def endless_body():
        nonlocal pulled
        for _ in range(10_000):
            pulled += 1
            yield b"x" * 1024

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=endless_body())

    out = await api_client(handler, max_response_bytes=4096).request("GET", "/public/x", BEARER)
    assert "truncated" in out and len(out) < 4096 + 200
    assert pulled <= 6  # stopped right after the cap, never drained the stream


async def test_help_center_oversized_response_is_an_error():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"article": {"body": "x" * 10_000}})

    with pytest.raises(SporfieApiHttpError, match="too large"):
        await hc_client(handler, max_response_bytes=1000).article(7, "en-us")


# ----- failures are tool errors, with sanitized text -----


async def test_html_error_pages_are_stripped_and_capped():
    # A 4xx page is the caller's to read, so its text is shown, without markup and short. (A 5xx
    # page is never shown at all: see test_error_bodies.py.)
    page = "<html><body><h1>Forbidden</h1><p>" + "detail " * 1000 + "</p></body></html>"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(403, html=page)

    with pytest.raises(SporfieApiHttpError) as err:
        await api_client(handler).request("GET", "/public/x", BEARER)
    assert err.value.status == 403
    assert "<" not in err.value.body and "Forbidden" in err.value.body
    assert len(err.value.body) <= 500 + len(" …")


async def test_json_error_bodies_drop_stack_traces():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            500,
            json={
                "error": "Internal",
                "message": "boom",
                "trace": "at com.x.Y(Y.java:1)",
                "exception": "java.lang.IllegalStateException",
            },
        )

    with pytest.raises(SporfieApiHttpError) as err:
        await api_client(handler).request("GET", "/public/x", BEARER)
    assert "boom" in err.value.body
    assert "trace" not in err.value.body and "IllegalStateException" not in err.value.body


async def test_backend_401_becomes_a_tool_error_with_a_hint(monkeypatch):
    recorder = Recorder(httpx.Response(401, json={"error": "invalid_bearer"}))
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    with pytest.raises(ToolError) as err:
        await srv.get_event("e1", ctx_with(AUTHED))
    assert str(err.value).startswith("HTTP 401:") and "rejected the token" in str(err.value)


@pytest.fixture(scope="module")
def mcp_http():
    """One HTTP client over the real ASGI app (its MCP session manager can only start once)."""
    importlib.reload(srv)
    with TestClient(srv.app, base_url="http://localhost:8080") as client:
        yield client


def _mcp_call(client: TestClient, tool: str, arguments: dict) -> dict:
    response = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        },
        headers={"Authorization": BEARER, "Accept": "application/json, text/event-stream"},
    )
    assert response.status_code == 200, response.text
    return response.json()["result"]


def test_initialize_reports_this_servers_version_not_the_sdks(mcp_http):
    response = mcp_http.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "0"},
            },
        },
        headers={"Accept": "application/json, text/event-stream"},
    )
    info = response.json()["result"]["serverInfo"]
    assert info["name"] == "sporfie-public-api"
    assert info["version"] == sporfie_public_server.__version__
    assert info["version"] != importlib.metadata.version("mcp")


def test_backend_error_is_is_error_over_the_protocol(monkeypatch, mcp_http):
    recorder = Recorder(httpx.Response(401, json={"error": "invalid_bearer"}))
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    result = _mcp_call(mcp_http, "get_event", {"event_key_or_external_id": "e1"})
    assert result["isError"] is True
    assert "HTTP 401" in result["content"][0]["text"]


def test_rejected_identifier_is_is_error_over_the_protocol(monkeypatch, mcp_http):
    recorder = Recorder()
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    result = _mcp_call(mcp_http, "unwatch_event", {"event_key_or_external_id": "e1#"})
    assert result["isError"] is True
    assert "Invalid event_key_or_external_id" in result["content"][0]["text"]
    assert recorder.requests == []


def test_success_is_not_is_error_over_the_protocol(monkeypatch, mcp_http):
    recorder = Recorder(httpx.Response(200, json={"sports": ["football"]}))
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    result = _mcp_call(mcp_http, "list_sports", {})
    assert result["isError"] is False
    assert "football" in result["content"][0]["text"]


# ----- request bodies are capped well below the SDK's 4 MiB -----


def _padded_tools_call(padding: int) -> bytes:
    """A valid tools/call whose ``_meta`` carries ``padding`` bytes the server has no use for."""
    return json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "list_sports", "arguments": {}, "_meta": {"pad": "x" * padding}},
        }
    ).encode()


_MCP_HEADERS = {
    "Authorization": BEARER,
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


def test_the_request_cap_defaults_to_256_kib_and_reaches_the_transport():
    assert load_config().max_request_bytes == 256 * 1024
    assert srv.mcp.settings.max_request_body_size == srv._CONFIG.max_request_bytes


def test_the_request_cap_can_be_set_from_the_environment(monkeypatch):
    monkeypatch.setenv("SPORFIE_MCP_MAX_REQUEST_BYTES", "4096")
    assert load_config().max_request_bytes == 4096


def test_a_body_over_the_cap_is_refused_before_it_is_parsed(monkeypatch, mcp_http):
    recorder = Recorder(httpx.Response(200, json={"sports": []}))
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    body = _padded_tools_call(srv._CONFIG.max_request_bytes + 1)

    response = mcp_http.post("/mcp", content=body, headers=_MCP_HEADERS)

    assert response.status_code == 413
    assert recorder.requests == []  # never reached a tool


def test_a_streamed_body_over_the_cap_is_refused_too(monkeypatch, mcp_http):
    """No Content-Length to check up front: the bytes are counted as they arrive."""
    recorder = Recorder(httpx.Response(200, json={"sports": []}))
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    body = _padded_tools_call(srv._CONFIG.max_request_bytes + 1)
    chunks = (body[i : i + 8192] for i in range(0, len(body), 8192))

    response = mcp_http.post("/mcp", content=chunks, headers=_MCP_HEADERS)

    assert response.status_code == 413
    assert recorder.requests == []


def test_a_body_under_the_cap_still_works(monkeypatch, mcp_http):
    recorder = Recorder(httpx.Response(200, json={"sports": ["football"]}))
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    body = _padded_tools_call(srv._CONFIG.max_request_bytes // 2)

    response = mcp_http.post("/mcp", content=body, headers=_MCP_HEADERS)

    assert response.status_code == 200
    assert "football" in response.json()["result"]["content"][0]["text"]


# ----- only the trusted client address is forwarded -----


async def test_forwards_only_the_trusted_public_client_address(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    monkeypatch.setattr(srv, "_CONFIG", dataclasses.replace(srv._CONFIG, trusted_proxy_hops=1))

    def forwarded_for(headers: dict, peer: str | None = "10.1.2.3"):
        return ctx_with({**AUTHED, **headers}, client_host=peer)

    await srv.list_sports(forwarded_for({"x-forwarded-for": "1.1.1.1, 9.9.9.9"}))
    assert recorder.requests[-1].headers["x-forwarded-for"] == "9.9.9.9"  # the trusted entry

    await srv.list_sports(forwarded_for({}, peer="8.8.4.4"))  # no proxy header: the peer
    assert recorder.requests[-1].headers["x-forwarded-for"] == "8.8.4.4"

    for headers, peer in [
        ({"x-forwarded-for": "not-an-address"}, "10.1.2.3"),  # junk is never relayed
        ({"x-forwarded-for": "10.9.9.9"}, "10.1.2.3"),  # private addresses are never relayed
        ({"x-forwarded-for": "127.0.0.1"}, None),
        ({"x-forwarded-for": "100.64.0.1"}, None),  # shared address space
        ({"x-forwarded-for": "fd00::1"}, None),  # IPv6 unique local
        ({}, None),  # unknown address
    ]:
        await srv.list_sports(forwarded_for(headers, peer))
        assert "x-forwarded-for" not in recorder.requests[-1].headers, headers


async def test_forwarded_for_is_ignored_without_a_trusted_proxy(monkeypatch):
    recorder = Recorder()
    monkeypatch.setattr(srv, "_CLIENT", api_client(recorder))
    monkeypatch.setattr(srv, "_CONFIG", dataclasses.replace(srv._CONFIG, trusted_proxy_hops=0))
    await srv.list_sports(ctx_with({**AUTHED, "x-forwarded-for": "9.9.9.9"}, client_host="8.8.4.4"))
    assert recorder.requests[-1].headers["x-forwarded-for"] == "8.8.4.4"


async def test_help_center_gets_neither_token_nor_address(monkeypatch):
    recorder = Recorder(httpx.Response(200, json={"results": []}))
    monkeypatch.setattr(srv, "_HC", hc_client(recorder))
    await srv.search_help_center("camera")
    request = recorder.requests[0]
    assert "authorization" not in request.headers and "x-forwarded-for" not in request.headers


def test_client_address_semantics():
    assert client_address(["1.1.1.1, 9.9.9.9"], "10.0.0.1", 1) == "9.9.9.9"
    assert client_address(["1.1.1.1", "9.9.9.9"], "10.0.0.1", 1) == "9.9.9.9"  # repeated headers
    assert client_address(["1.1.1.1, 8.8.8.8, 9.9.9.9"], "10.0.0.1", 2) == "8.8.8.8"
    assert client_address(["1.1.1.1, 9.9.9.9"], "10.0.0.1", 0) == "10.0.0.1"  # header ignored
    assert client_address(["9.9.9.9"], "10.0.0.1", 2) == "10.0.0.1"  # shorter than the chain
    assert client_address(["1.1.1.1, bogus"], "10.0.0.1", 1) == "10.0.0.1"
    assert client_address([], None, 1) is None
    assert client_address(["2001:DB8::1"], None, 1) == "2001:db8::1"


def test_only_global_addresses_are_forwardable():
    assert forwardable("9.9.9.9") and forwardable("2606:4700::1111")
    for address in [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.1.1",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "bogus",
        "",
        None,
    ]:
        assert not forwardable(address), address


def test_rate_limit_key_groups_ipv6_by_64():
    assert rate_limit_key("2001:db8:1:2::1") == rate_limit_key("2001:db8:1:2:ffff::9")
    assert rate_limit_key("2001:db8:1:2::1") != rate_limit_key("2001:db8:1:3::1")
    assert rate_limit_key("203.0.113.9") == "203.0.113.9"
    assert rate_limit_key(None) == "unknown"


# ----- the rate-limit table stays bounded -----


def _limited(limit: int, **kwargs) -> TestClient:
    async def ok(_: object) -> JSONResponse:
        return JSONResponse({"ok": True})

    app = Starlette(routes=[Route("/mcp", ok, methods=["GET"])])
    app.add_middleware(RateLimitMiddleware, limit_per_minute=limit, **kwargs)
    return TestClient(app)


def test_rate_limit_table_is_hard_bounded():
    limiter = RateLimitMiddleware(app=None, limit_per_minute=5, max_tracked=100)
    for i in range(5_000):
        limiter._over_limit(f"198.51.{i // 256}.{i % 256}")
    assert len(limiter._windows) == 100


def test_rate_limit_ipv6_neighbours_share_a_bucket():
    client = _limited(1, trusted_proxy_hops=1)
    assert client.get("/mcp", headers={"X-Forwarded-For": "2001:db8::1"}).status_code == 200
    assert client.get("/mcp", headers={"X-Forwarded-For": "2001:db8::2"}).status_code == 429


def test_rate_limit_ignores_forwarded_for_by_default():
    client = _limited(1)
    assert client.get("/mcp", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert client.get("/mcp", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 429


# ----- tool annotations -----


async def test_every_tool_carries_accurate_annotations():
    tools = {t.name: t.annotations for t in await srv.mcp.list_tools()}
    assert len(tools) == 19 and all(a is not None for a in tools.values())
    read_only = {n for n in tools if n.startswith(("get_", "list_", "search_", "lookup_"))}
    assert {n for n, a in tools.items() if a.readOnlyHint} == read_only
    destructive = {
        "update_event",
        "close_event",
        "delete_event",
        "update_moment",
        "delete_moment",
        "watch_event",
        "unwatch_event",
    }
    assert {n for n, a in tools.items() if not a.readOnlyHint and a.destructiveHint} == destructive
    assert tools["watch_event"].openWorldHint is True


async def test_only_calls_that_are_safe_to_repeat_are_advertised_as_idempotent():
    tools = {t.name: t for t in await srv.mcp.list_tools()}
    idempotent = {
        "update_event",
        "delete_event",
        "update_moment",
        "delete_moment",
        "watch_event",
        "unwatch_event",
    }
    assert {
        n
        for n, t in tools.items()
        if not t.annotations.readOnlyHint and t.annotations.idempotentHint
    } == idempotent
    # Closing rewrites the end time to "now", so a repeat is not a no-op, and it says so.
    close = tools["close_event"]
    assert close.annotations.idempotentHint is False and close.annotations.destructiveHint is True
    assert 're-sets the end time to the new "now"' in close.description
