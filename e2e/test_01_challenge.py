"""A client arrives with nothing: what it is told, and that nothing is served to it."""

from __future__ import annotations

from . import oauth, raw


def test_the_health_probe_answers(http, settings):
    response = http.get(f"{settings.origin}/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_a_request_without_a_token_gets_the_discovery_challenge(http, settings, oauth_on):
    response = raw.post(http, settings.mcp_url)
    assert response.status_code == 401
    challenge = oauth.parse_challenge(response.headers["www-authenticate"])
    metadata = f"{settings.expected_origin}/.well-known/oauth-protected-resource"
    assert challenge.get("resource_metadata") == metadata
    assert "error" not in challenge, "no credentials were sent, so there is nothing to call invalid"


def test_the_tool_list_needs_a_token_too(http, settings, oauth_on):
    listing = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    assert raw.post(http, settings.mcp_url, listing).status_code == 401


def test_a_made_up_token_is_turned_away_at_the_first_tool_call(http, settings, oauth_on):
    response = raw.post(
        http, settings.mcp_url, raw.tool_call("list_sports"), token=raw.MADE_UP_TOKEN
    )
    assert response.status_code == 401
    challenge = oauth.parse_challenge(response.headers["www-authenticate"])
    assert challenge.get("error") == "invalid_token"


def test_an_oversized_body_is_refused_before_it_is_parsed(http, settings):
    body = raw.tool_call("list_sports")
    body["params"]["_meta"] = {"padding": "x" * (300 * 1024)}
    response = raw.post(http, settings.mcp_url, body, token=raw.MADE_UP_TOKEN)
    assert response.status_code == 413
