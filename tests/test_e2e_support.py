"""The helpers of the end-to-end suite (e2e/), tested offline.

The suite itself needs a deployed server. Its helpers do not, and a mistake in them would show up
as a confusing failure against a real environment, so they are checked here with the rest.
"""

from __future__ import annotations

import base64
import hashlib
import json
import stat
import threading
import time

import httpx
import pytest
import uvicorn

from e2e import oauth, settings
from e2e.mcp_client import McpClient, ToolResult

ISSUER = "https://auth.example"
RESOURCE = "https://mcp.example/mcp"
DISCOVERY = oauth.Discovery(
    resource=RESOURCE,
    issuer=ISSUER,
    authorization_endpoint=f"{ISSUER}/oauth/authorize",
    token_endpoint=f"{ISSUER}/oauth/token",
    registration_endpoint=f"{ISSUER}/oauth/register",
)


def _jwt(claims: dict) -> str:
    def part(value: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b"=").decode()

    return f"{part({'alg': 'none'})}.{part(claims)}.signature"


def _grant(expires_in: float = 3600, access: str = "access-1", refresh: str = "refresh-1"):
    return oauth.Grant("client-1", access, refresh, time.time() + expires_in, RESOURCE, ISSUER)


# ---------------------------------------------------------------- challenge and discovery


def test_a_bearer_challenge_is_parsed_into_its_parameters():
    header = 'Bearer error="invalid_token", resource_metadata="https://mcp.example/.well-known/x"'
    assert oauth.parse_challenge(header) == {
        "error": "invalid_token",
        "resource_metadata": "https://mcp.example/.well-known/x",
    }
    assert oauth.parse_challenge('bearer realm="r"') == {"realm": "r"}


def test_another_scheme_is_not_a_bearer_challenge():
    assert oauth.parse_challenge('Basic realm="r"') == {}
    assert oauth.parse_challenge("") == {}


def _transport(challenge_status: int = 401) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if request.method == "POST" and url == RESOURCE:
            header = 'Bearer resource_metadata="https://mcp.example/.well-known/prm"'
            return httpx.Response(challenge_status, headers={"www-authenticate": header})
        if url == "https://mcp.example/.well-known/prm":
            return httpx.Response(
                200, json={"resource": RESOURCE, "authorization_servers": [ISSUER]}
            )
        if url == f"{ISSUER}/.well-known/oauth-authorization-server":
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "authorization_endpoint": DISCOVERY.authorization_endpoint,
                    "token_endpoint": DISCOVERY.token_endpoint,
                    "registration_endpoint": DISCOVERY.registration_endpoint,
                },
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_discovery_follows_the_challenge_to_the_authorization_server():
    with httpx.Client(transport=_transport()) as http:
        assert oauth.discover(RESOURCE, http) == DISCOVERY


def test_discovery_says_so_when_the_server_does_not_challenge():
    with (
        httpx.Client(transport=_transport(challenge_status=200)) as http,
        pytest.raises(oauth.OAuthFlowError, match="is OAuth enabled"),
    ):
        oauth.discover(RESOURCE, http)


# ---------------------------------------------------------------- PKCE and the authorize URL


def test_the_pkce_challenge_is_the_hash_of_the_verifier():
    pkce = oauth.Pkce.new()
    digest = hashlib.sha256(pkce.verifier.encode()).digest()
    assert pkce.challenge == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert len(pkce.verifier) >= 43  # RFC 7636 minimum
    assert oauth.Pkce.new().verifier != pkce.verifier


def test_the_authorize_url_asks_for_pkce_and_binds_the_resource():
    pkce = oauth.Pkce.new()
    url = oauth.authorize_url(DISCOVERY, "client-1", "http://localhost:8787/callback", pkce, "s1")
    query = httpx.URL(url).params
    assert str(httpx.URL(url)).startswith(DISCOVERY.authorization_endpoint)
    assert query["code_challenge_method"] == "S256"
    assert query["code_challenge"] == pkce.challenge
    assert query["resource"] == RESOURCE
    assert query["state"] == "s1"
    assert query["response_type"] == "code"


# ---------------------------------------------------------------- tokens


def test_jwt_claims_are_read_without_trusting_them():
    assert oauth.jwt_claims(_jwt({"aud": RESOURCE, "exp": 5}))["aud"] == RESOURCE
    assert oauth.jwt_claims("not-a-jwt") == {}
    assert oauth.jwt_claims("a.!!!.c") == {}


def test_a_grant_is_refreshed_before_it_runs_out():
    assert not _grant(expires_in=3600).needs_refresh()
    assert _grant(expires_in=oauth.REFRESH_MARGIN_S - 1).needs_refresh()
    assert _grant(expires_in=-5).needs_refresh()


def test_the_token_store_keeps_its_file_private(tmp_path):
    store = oauth.TokenStore(tmp_path / "state" / "tokens.json")
    store.put_grant(_grant())
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.parent.stat().st_mode) == 0o700
    assert store.grant().access_token == "access-1"


def test_the_token_store_remembers_the_client_only_for_the_same_issuer_and_redirect(tmp_path):
    store = oauth.TokenStore(tmp_path / "tokens.json")
    redirect = "http://localhost:8787/callback"
    store.put_client(ISSUER, "client-1", [redirect])
    assert store.client_id(ISSUER, redirect) == "client-1"
    assert store.client_id("https://other.example", redirect) is None
    assert store.client_id(ISSUER, "http://localhost:9999/callback") is None


def test_a_fresh_access_token_is_used_as_it_is(tmp_path):
    store = oauth.TokenStore(tmp_path / "tokens.json")
    store.put_grant(_grant(expires_in=3600))

    def refuse(request: httpx.Request) -> httpx.Response:  # any request would be a bug
        raise AssertionError(f"unexpected request to {request.url}")

    with httpx.Client(transport=httpx.MockTransport(refuse)) as http:
        assert store.access_token(http, DISCOVERY) == "access-1"


def test_a_stale_access_token_is_refreshed_and_the_new_pair_is_kept(tmp_path):
    store = oauth.TokenStore(tmp_path / "tokens.json")
    store.put_grant(_grant(expires_in=10))
    seen: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(httpx.QueryParams(request.content.decode()))
        body = {"access_token": "access-2", "refresh_token": "refresh-2", "expires_in": 3600}
        return httpx.Response(200, json=body)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http:
        assert store.access_token(http, DISCOVERY) == "access-2"
    assert seen["grant_type"] == "refresh_token"
    assert seen["refresh_token"] == "refresh-1"
    assert seen["resource"] == RESOURCE
    assert store.grant().refresh_token == "refresh-2"


def test_a_grant_that_cannot_be_refreshed_tells_the_user_to_sign_in_again(tmp_path):
    store = oauth.TokenStore(tmp_path / "tokens.json")
    store.put_grant(_grant(expires_in=10))
    dead = httpx.MockTransport(lambda request: httpx.Response(400, json={"error": "invalid_grant"}))
    with (
        httpx.Client(transport=dead) as http,
        pytest.raises(oauth.OAuthFlowError, match="e2e.login"),
    ):
        store.access_token(http, DISCOVERY)


# ---------------------------------------------------------------- the loopback callback


def test_an_approval_from_an_abandoned_link_is_ignored_and_the_right_one_is_taken():
    with oauth.CallbackServer(0) as callback:
        port = callback.port
        with httpx.Client() as http:
            http.get(f"http://127.0.0.1:{port}/callback?state=old&code=stale")
            http.get(f"http://127.0.0.1:{port}/callback?state=new&code=fresh")
        assert callback.wait_for("new", timeout_s=5)["code"] == "fresh"


def test_waiting_for_an_approval_that_never_comes_times_out():
    with (
        oauth.CallbackServer(0) as callback,
        pytest.raises(oauth.OAuthFlowError, match="no approval"),
    ):
        callback.wait_for("never", timeout_s=0.2)


# ---------------------------------------------------------------- tool results


def test_a_failure_behind_the_sdks_prefix_is_recognised():
    text = 'Error executing tool get_event: HTTP 404: {"code":"NotFound"}'
    assert ToolResult("get_event", {}, text, is_error=True).http_status == 404


def test_a_failure_reported_as_a_success_is_flagged():
    failure = ToolResult("get_event", {}, "HTTP 404: not found", is_error=False)
    assert failure.unflagged_failure
    assert not ToolResult("get_event", {}, "HTTP 404: not found", is_error=True).unflagged_failure
    assert not ToolResult("list_sports", {}, '["soccer"]', is_error=False).unflagged_failure


def test_a_result_that_is_not_json_says_what_it_was():
    with pytest.raises(AssertionError, match="did not return JSON"):
        ToolResult("list_sports", {}, "plain words", is_error=False).json()


# ---------------------------------------------------------------- settings


def test_without_a_server_url_there_is_nothing_to_test(monkeypatch):
    monkeypatch.delenv("E2E_MCP_URL", raising=False)
    assert settings.load() is None


def test_settings_are_read_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("E2E_MCP_URL", "https://mcp.sporfie.com/mcp/")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.delenv("E2E_TOKEN_FILE", raising=False)
    monkeypatch.delenv("E2E_EXPECTED_RESOURCE", raising=False)
    loaded = settings.load()
    assert loaded.mcp_url == "https://mcp.sporfie.com/mcp"
    assert loaded.expected_resource == "https://mcp.sporfie.com/mcp"
    assert loaded.origin == "https://mcp.sporfie.com"
    assert loaded.is_production
    assert loaded.token_file == tmp_path / "sporfie-public-mcp" / "e2e-mcp.sporfie.com.json"


def test_a_url_that_is_not_http_is_refused(monkeypatch):
    monkeypatch.setenv("E2E_MCP_URL", "ftp://mcp.example/mcp")
    with pytest.raises(ValueError, match="http"):
        settings.load()


# ---------------------------------------------------------------- the client, against a real server


@pytest.fixture
def local_server():
    """The real ASGI app on an ephemeral port, in this process."""
    import sporfie_public_server.server as srv

    server = uvicorn.Server(uvicorn.Config(srv.app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    assert server.started, "the local server did not start"
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}/mcp"
    server.should_exit = True
    thread.join(timeout=10)


def test_the_client_opens_a_session_lists_tools_and_reports_a_failure(local_server):
    client = McpClient(local_server, "any-token", min_interval_s=0).start()
    try:
        assert client.initialized.serverInfo.name == "sporfie-public-api"
        assert "get_event" in {tool.name for tool in client.list_tools()}
        # An identifier that is not a key is refused here, before any request to the API.
        refused = client.call("get_event", {"event_key_or_external_id": "a/b"})
        assert refused.is_error and not refused.unflagged_failure
        assert client.results == [refused]
    finally:
        client.stop()
