"""A connection's lifetime: consent, refresh, rotation and theft detection.

A person has to approve one consent screen, so this only runs with E2E_INTERACTIVE=1. It uses a
client of its own, so the grant the other tests use is left alone, and its last test revokes the
connection it made.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import pytest

from . import oauth, raw
from .mcp_client import McpClient

pytestmark = pytest.mark.interactive

# After a refresh the server forgives one replay of the previous refresh token for this long (a
# client that lost the answer may retry). Past it, a replay is taken for theft.
REFRESH_GRACE_S = 10


@dataclass
class Connection:
    client_id: str
    grant: oauth.Grant
    superseded: oauth.Grant | None = None


@pytest.fixture(scope="module")
def connection(request, settings, http, discovery) -> Connection:
    capture = request.config.pluginmanager.getplugin("capturemanager")

    def announce(text: str) -> None:
        with capture.global_and_fixture_disabled():  # the person needs to see the link
            print(f"\n{text}", flush=True)

    registration = oauth.register(
        http,
        discovery,
        [oauth.redirect_uri_for(settings.redirect_port)],
        client_name="Sporfie MCP e2e (connection lifecycle)",
    )
    assert registration.status_code == 201, registration.text
    client_id = registration.json()["client_id"]
    tokens = oauth.authenticate(
        http, discovery, client_id, port=settings.redirect_port, announce=announce
    )
    return Connection(client_id, oauth.Grant.from_token_response(tokens, client_id, discovery))


def _status(http, settings, token: str) -> int:
    """What the server says to a tool call made with ``token``: 200, or 401 for a dead token."""
    return raw.post(http, settings.mcp_url, raw.tool_call("list_sports"), token=token).status_code


def test_the_access_token_is_bound_to_this_server(connection, discovery):
    audience = oauth.jwt_claims(connection.grant.access_token).get("aud")
    audiences = [audience] if isinstance(audience, str) else audience
    assert discovery.resource in audiences
    assert connection.grant.refresh_token
    assert connection.grant.expires_at > time.time()


def test_the_token_opens_a_session(settings, connection):
    client = McpClient(
        settings.mcp_url, connection.grant.access_token, settings.min_interval_s
    ).start()
    try:
        assert not client.call("list_sports").is_error
    finally:
        client.stop()


def test_refreshing_replaces_the_access_token(http, settings, discovery, connection):
    old = connection.grant
    connection.grant = oauth.refresh_grant(http, discovery, old)
    connection.superseded = old
    assert connection.grant.access_token != old.access_token
    assert connection.grant.refresh_token != old.refresh_token
    assert _status(http, settings, connection.grant.access_token) == 200
    assert _status(http, settings, old.access_token) == 401, "the superseded token still works"


def test_a_refresh_naming_another_client_is_refused_and_changes_nothing(
    http, settings, discovery, connection
):
    response = oauth.token_request(
        http,
        discovery,
        {
            "grant_type": "refresh_token",
            "refresh_token": connection.grant.refresh_token,
            "client_id": "not-the-client-this-was-issued-to",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_grant"
    # Nothing was rotated or revoked: the connection's own token still works.
    assert _status(http, settings, connection.grant.access_token) == 200


def test_replaying_a_token_replaced_two_rotations_ago_revokes_the_whole_connection(
    http, settings, discovery, connection
):
    """The older token is not the previous one any more: only a server that remembers every token it
    replaced can tell it is a replay (needs a backend with SPOR-6153 part 3)."""
    assert connection.superseded is not None, "the refresh test has not run"
    older = connection.superseded
    connection.grant = oauth.refresh_grant(http, discovery, connection.grant)  # one more rotation
    time.sleep(REFRESH_GRACE_S + 1)
    replay = oauth.token_request(
        http,
        discovery,
        {
            "grant_type": "refresh_token",
            "refresh_token": older.refresh_token,
            "client_id": connection.client_id,
        },
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    assert _status(http, settings, connection.grant.access_token) == 401, "a theft left it alive"
    newest = oauth.token_request(
        http,
        discovery,
        {
            "grant_type": "refresh_token",
            "refresh_token": connection.grant.refresh_token,
            "client_id": connection.client_id,
        },
    )
    assert newest.status_code == 400
