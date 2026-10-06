"""OAuth resource-server behavior: metadata doc and 401 challenges, gated on the issuer."""

from __future__ import annotations

import importlib
import os

import httpx
import pytest
from starlette.testclient import TestClient

from sporfie_public_server.client import SporfieApiClient, SporfieApiOverloaded

BASE_URL = "http://localhost:8080"  # a Host the transport's DNS-rebinding check accepts
ACCEPT = {"Accept": "application/json, text/event-stream"}
TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


def _load_app(monkeypatch: pytest.MonkeyPatch, issuer: str):
    """Reload the server module with a chosen issuer env (config is read at import)."""
    if issuer:
        monkeypatch.setenv("SPORFIE_MCP_OAUTH_ISSUER", issuer)
    else:
        monkeypatch.delenv("SPORFIE_MCP_OAUTH_ISSUER", raising=False)
    monkeypatch.setenv("SPORFIE_MCP_PUBLIC_URL", "https://mcp.sporfie.com")
    monkeypatch.setenv("SPORFIE_MCP_RATE_LIMIT_PER_MINUTE", "0")  # don't interfere
    import sporfie_public_server.server as srv

    return importlib.reload(srv)


@pytest.fixture(autouse=True)
def _restore_module():
    yield
    # Leave the module in its default (issuer-unset) state for other test files.
    for key in (
        "SPORFIE_MCP_OAUTH_ISSUER",
        "SPORFIE_MCP_PUBLIC_URL",
        "SPORFIE_MCP_RATE_LIMIT_PER_MINUTE",
    ):
        os.environ.pop(key, None)
    import sporfie_public_server.server as srv

    importlib.reload(srv)


def _backend(status: int, body: dict) -> SporfieApiClient:
    return SporfieApiClient(
        base_url="http://backend.test",
        timeout_s=5,
        max_response_chars=20000,
        transport=httpx.MockTransport(lambda _: httpx.Response(status, json=body)),
    )


def _post_tool(client: TestClient, headers) -> httpx.Response:
    return client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_event", "arguments": {"event_key_or_external_id": "e1"}},
        },
        headers=headers,
    )


def _call_tool(client: TestClient, authorization: str) -> httpx.Response:
    return _post_tool(client, {**ACCEPT, "Authorization": authorization})


def _recording_backend(seen: list) -> SporfieApiClient:
    """An upstream client that records the Authorization header of every request it gets."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("authorization"))
        return httpx.Response(200, json={"eventKey": "e1"})

    return SporfieApiClient(
        base_url="http://backend.test",
        timeout_s=5,
        max_response_chars=20000,
        transport=httpx.MockTransport(handler),
    )


def test_oauth_off_by_default_no_metadata_no_challenge(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = _load_app(monkeypatch, issuer="")
    # Context-manager form runs the MCP lifespan so a request reaching the MCP app doesn't
    # trip "task group is not initialized".
    with TestClient(srv.app, base_url=BASE_URL) as client:
        assert client.get("/.well-known/oauth-protected-resource").status_code == 404
        # Unauthenticated MCP request is NOT challenged when OAuth is off (header-only mode).
        resp = client.post("/mcp", json=TOOLS_LIST, headers=ACCEPT)
        assert resp.status_code == 200 and "get_event" in resp.text


def test_oauth_off_rejected_token_is_a_tool_error_not_a_challenge(monkeypatch) -> None:
    srv = _load_app(monkeypatch, issuer="")
    monkeypatch.setattr(srv, "_CLIENT", _backend(401, {"code": "invalid_bearer"}))
    with TestClient(srv.app, base_url=BASE_URL) as client:
        resp = _call_tool(client, "Bearer expired-token")
    assert resp.status_code == 200
    assert resp.json()["result"]["isError"] is True


def test_metadata_served_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    client = TestClient(srv.app, base_url=BASE_URL)
    resp = client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == "https://mcp.sporfie.com/mcp"
    assert body["authorization_servers"] == ["https://api.sporfie.com"]
    assert "header" in body["bearer_methods_supported"]
    # The path-suffixed variant is served too.
    assert client.get("/.well-known/oauth-protected-resource/mcp").status_code == 200


@pytest.mark.parametrize("authorization", [None, "", "Basic dXNlcjpwYXNz", "Bearer", "Bearer  "])
def test_challenge_when_enabled_without_a_bearer_token(monkeypatch, authorization) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    client = TestClient(srv.app, base_url=BASE_URL)
    headers = dict(ACCEPT)
    if authorization is not None:
        headers["Authorization"] = authorization
    resp = client.post("/mcp", json=TOOLS_LIST, headers=headers)
    assert resp.status_code == 401
    www = resp.headers["WWW-Authenticate"]
    assert www.startswith("Bearer ") and "error=" not in www
    assert 'resource_metadata="https://mcp.sporfie.com/.well-known/oauth-protected-resource"' in www


def test_more_than_one_authorization_header_is_challenged(monkeypatch) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    client = TestClient(srv.app, base_url=BASE_URL)
    headers = [*ACCEPT.items(), ("Authorization", "Bearer a"), ("Authorization", "Bearer b")]
    resp = client.post("/mcp", json=TOOLS_LIST, headers=headers)
    assert resp.status_code == 401
    www = resp.headers["WWW-Authenticate"]
    assert www.startswith("Bearer ") and "error=" not in www and "resource_metadata=" in www


@pytest.mark.parametrize("scheme", ["Bearer", "bearer", "BEARER", "bEaReR"])
def test_bearer_scheme_is_case_insensitive_at_the_challenge(monkeypatch, scheme) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    with TestClient(srv.app, base_url=BASE_URL) as client:
        headers = {**ACCEPT, "Authorization": f"{scheme} whatever"}
        resp = client.post("/mcp", json=TOOLS_LIST, headers=headers)
    assert resp.status_code == 200 and "get_event" in resp.text


def test_has_bearer_token_reads_every_authorization_header() -> None:
    from sporfie_public_server.oauth import _has_bearer_token

    def scope(*values: bytes) -> dict:
        return {"headers": [(b"authorization", v) for v in values] + [(b"host", b"x")]}

    assert _has_bearer_token(scope(b"Bearer a")) and _has_bearer_token(scope(b"bearer a"))
    assert not _has_bearer_token(scope())
    assert not _has_bearer_token(scope(b"Bearer a", b"Bearer b"))
    assert not _has_bearer_token(scope(b"Bearer a", b"Bearer a"))
    assert not _has_bearer_token(scope(b"Bearer a", b"Basic x"))
    for unusable in (b"", b"Bearer", b"Bearer a b", b"Basic dXNlcjpwYXNz", b"Bearertok"):
        assert not _has_bearer_token(scope(unusable)), unusable


def test_a_lowercase_scheme_reaches_the_api_in_canonical_form(monkeypatch) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    seen: list = []
    monkeypatch.setattr(srv, "_CLIENT", _recording_backend(seen))
    with TestClient(srv.app, base_url=BASE_URL) as client:
        resp = _call_tool(client, "bearer valid-token")
    assert resp.status_code == 200 and resp.json()["result"]["isError"] is False
    assert seen == ["Bearer valid-token"]  # the API strips a case-sensitive "Bearer "


def test_two_authorization_headers_are_a_tool_error_when_oauth_is_off(monkeypatch) -> None:
    srv = _load_app(monkeypatch, issuer="")
    seen: list = []
    monkeypatch.setattr(srv, "_CLIENT", _recording_backend(seen))
    headers = [*ACCEPT.items(), ("Authorization", "Bearer a"), ("Authorization", "Bearer b")]
    with TestClient(srv.app, base_url=BASE_URL) as client:
        resp = _post_tool(client, headers)
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["isError"] is True
    assert "exactly one Authorization header" in result["content"][0]["text"]
    assert seen == []  # neither credential was forwarded


def test_health_and_discovery_never_challenged(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    client = TestClient(srv.app, base_url=BASE_URL)
    assert client.get("/health").status_code == 200
    assert client.get("/.well-known/oauth-protected-resource").status_code == 200


def test_authorization_header_passes_challenge(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    # With a bearer present, the challenge middleware lets it through (validity is the API's
    # job). Context-manager form runs the MCP lifespan so the request can reach the MCP app.
    with TestClient(srv.app, base_url=BASE_URL) as client:
        resp = client.post(
            "/mcp", json=TOOLS_LIST, headers={**ACCEPT, "Authorization": "Bearer whatever"}
        )
    assert resp.status_code == 200 and "get_event" in resp.text


def test_token_rejected_by_the_api_becomes_invalid_token_challenge(monkeypatch) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    monkeypatch.setattr(srv, "_CLIENT", _backend(401, {"code": "invalid_bearer"}))
    with TestClient(srv.app, base_url=BASE_URL) as client:
        resp = _call_tool(client, "Bearer expired-token")
    assert resp.status_code == 401
    www = resp.headers["WWW-Authenticate"]
    assert 'error="invalid_token"' in www
    assert 'resource_metadata="https://mcp.sporfie.com/.well-known/oauth-protected-resource"' in www
    assert resp.json()["error"] == "invalid_token"


def test_permission_denial_stays_a_tool_error_when_enabled(monkeypatch) -> None:
    # The API also answers 401 when a valid token may not act on a company. That must not send
    # the client into a re-authorization loop.
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    monkeypatch.setattr(srv, "_CLIENT", _backend(401, {"code": "Unauthorized", "message": "no"}))
    with TestClient(srv.app, base_url=BASE_URL) as client:
        resp = _call_tool(client, "Bearer valid-token")
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["isError"] is True and "HTTP 401" in result["content"][0]["text"]


class _Busy:
    """An upstream client that sheds every call, as a saturated one does."""

    async def request(self, *args, **kwargs) -> str:
        raise SporfieApiOverloaded("The server is busy; retry shortly.")


def test_overload_is_not_mistaken_for_a_rejected_token(monkeypatch) -> None:
    # Shedding a call says nothing about the token: no 401 challenge, or clients would send the
    # user back through sign-in every time the server is busy.
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    monkeypatch.setattr(srv, "_CLIENT", _Busy())
    with TestClient(srv.app, base_url=BASE_URL) as client:
        resp = _call_tool(client, "Bearer valid-token")
    assert resp.status_code == 200 and "WWW-Authenticate" not in resp.headers
    result = resp.json()["result"]
    assert result["isError"] is True and "busy" in result["content"][0]["text"]


def test_successful_call_is_untouched_when_enabled(monkeypatch) -> None:
    srv = _load_app(monkeypatch, issuer="https://api.sporfie.com")
    monkeypatch.setattr(srv, "_CLIENT", _backend(200, {"eventKey": "e1"}))
    with TestClient(srv.app, base_url=BASE_URL) as client:
        resp = _call_tool(client, "Bearer valid-token")
    assert resp.status_code == 200
    result = resp.json()["result"]
    assert result["isError"] is False and "e1" in result["content"][0]["text"]
