"""The sign-in a user goes through: discovery, registration, and what the server refuses."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlsplit

import pytest

from . import oauth

# What Cursor registers: its own URL scheme, and the loopback address it listens on.
CURSOR_REDIRECTS = [
    "cursor://anysphere.cursor-mcp/oauth/callback",
    "http://localhost:8787/callback",
]


@pytest.fixture(scope="module")
def cursor_client(http, discovery) -> dict:
    """One client registered the way Cursor registers itself (one record per run)."""
    response = oauth.register(http, discovery, CURSOR_REDIRECTS, client_name="Cursor")
    assert response.status_code == 201, response.text
    return response.json()


def test_the_resource_describes_itself(http, settings, oauth_on):
    response = http.get(f"{settings.origin}/.well-known/oauth-protected-resource")
    assert response.status_code == 200
    metadata = response.json()
    assert metadata["resource"] == settings.expected_resource
    assert len(metadata["authorization_servers"]) == 1
    assert metadata["bearer_methods_supported"] == ["header"]


def test_the_suffixed_metadata_url_some_clients_try_is_served_too(http, settings, oauth_on):
    plain = http.get(f"{settings.origin}/.well-known/oauth-protected-resource")
    suffixed = http.get(f"{settings.origin}/.well-known/oauth-protected-resource/mcp")
    assert suffixed.status_code == 200
    assert suffixed.json() == plain.json()


def test_the_authorization_server_supports_only_what_a_public_client_needs(http, discovery):
    response = http.get(f"{discovery.issuer}/.well-known/oauth-authorization-server")
    metadata = response.json()
    assert metadata["issuer"] == discovery.issuer
    assert metadata["code_challenge_methods_supported"] == ["S256"]
    assert metadata["token_endpoint_auth_methods_supported"] == ["none"]
    assert set(metadata["grant_types_supported"]) == {"authorization_code", "refresh_token"}
    assert metadata["response_types_supported"] == ["code"]


def test_registration_accepts_what_cursor_sends(cursor_client):
    assert cursor_client["client_id"]
    assert cursor_client["redirect_uris"] == CURSOR_REDIRECTS
    assert cursor_client["token_endpoint_auth_method"] == "none"


@pytest.mark.parametrize(
    "uri",
    [
        "http://attacker.example/callback",  # plain http is for loopback only
        "https://app.example/callback#fragment",
        "https://user:secret@app.example/callback",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "cursor://attacker.example/oauth/callback",  # another app under Cursor's scheme
        "cursor://anysphere.cursor-mcp/oauth/callback?next=elsewhere",
        "cursor://anysphere.cursor-mcp:1234/oauth/callback",
        "otherapp://anysphere.cursor-mcp/oauth/callback",  # a scheme nobody is allowed
    ],
)
def test_registration_refuses_redirects_that_could_leak_a_code(http, discovery, uri):
    response = oauth.register(http, discovery, [uri])
    assert response.status_code == 400, f"{uri} was accepted: {response.text}"
    assert response.json()["error"] == "invalid_redirect_uri"


def test_registration_needs_a_redirect(http, discovery):
    response = oauth.register(http, discovery, [])
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_redirect_uri"


def _authorize(http, discovery, client, **changes):
    """GET the authorization endpoint with a valid request, changed as asked. Never followed."""
    pkce = oauth.Pkce.new()
    url = oauth.authorize_url(
        discovery, client["client_id"], "http://localhost:8787/callback", pkce, "state-1"
    )
    parts = dict(parse_qsl(urlsplit(url).query))
    parts.update(changes)
    kept = {k: v for k, v in parts.items() if v is not None}
    return http.get(discovery.authorization_endpoint, params=kept, follow_redirects=False)


def test_a_valid_authorization_request_goes_to_the_consent_screen(http, discovery, cursor_client):
    response = _authorize(http, discovery, cursor_client)
    assert response.status_code == 302
    assert "/oauth/consent" in response.headers["location"]


@pytest.mark.parametrize(
    "changes",
    [
        {"code_challenge": None},  # PKCE is mandatory
        {"code_challenge_method": "plain"},  # and only S256 is accepted
        {"redirect_uri": "http://localhost:9999/elsewhere"},  # not one the client registered
        {"client_id": "not-a-registered-client"},
        {"response_type": "token"},  # no implicit flow
    ],
)
def test_a_malformed_authorization_request_is_an_error_page_not_a_redirect(
    http, discovery, cursor_client, changes
):
    response = _authorize(http, discovery, cursor_client, **changes)
    assert response.status_code == 400
    assert "location" not in response.headers


def test_a_token_is_never_issued_for_another_resource(http, discovery, cursor_client):
    response = _authorize(http, discovery, cursor_client, resource="https://elsewhere.example/mcp")
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("http://localhost:8787/callback?")
    query = dict(parse_qsl(urlsplit(location).query))
    assert query["error"] == "invalid_target"
    assert query["state"] == "state-1"
    assert "code" not in query


def test_the_token_endpoint_refuses_a_code_it_never_issued(http, discovery, cursor_client):
    response = oauth.token_request(
        http,
        discovery,
        {
            "grant_type": "authorization_code",
            "code": "a-code-nobody-issued",
            "client_id": cursor_client["client_id"],
            "redirect_uri": "http://localhost:8787/callback",
            "code_verifier": "v" * 64,
            "resource": discovery.resource,
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"


def test_the_token_endpoint_refuses_a_refresh_token_it_never_issued(http, discovery, cursor_client):
    response = oauth.token_request(
        http,
        discovery,
        {
            "grant_type": "refresh_token",
            "refresh_token": "a-refresh-token-nobody-issued",
            "client_id": cursor_client["client_id"],
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
