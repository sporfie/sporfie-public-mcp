"""OAuth 2.1 resource-server glue (MCP auth spec 2025-06-18, RFC 9728, RFC 6750).

This server is credential-less: it never validates tokens itself (the Sporfie API does, on every
/public call). Its OAuth duties are to:
  (a) advertise which authorization server issues tokens for it;
  (b) challenge MCP requests that carry no bearer token, so clients start the OAuth flow;
  (c) turn "the API rejected this token" into an HTTP 401 ``invalid_token`` challenge, so
      clients refresh or re-authorize instead of showing tool errors until the user reconnects.

All of it is gated on ``config.oauth_issuer``: empty means everything here is inert and the
server behaves like the header-only version. Set the issuer to turn one-click connect on.
"""

from __future__ import annotations

import json
from collections.abc import MutableMapping
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .auth import bearer_token

# Paths that must stay reachable WITHOUT a token even when the challenge is armed: the health
# probe, and OAuth discovery itself (a 401 on the metadata doc would be a discovery loop).
_UNCHALLENGED_PREFIXES = ("/health", "/.well-known/")

# Set on the ASGI scope by the tool layer when the API rejected the caller's token.
TOKEN_REJECTED = "sporfie.mcp.token_rejected"


def protected_resource_metadata(config) -> dict:
    """RFC 9728 payload advertising this resource and its authorization server(s)."""
    resource = f"{config.public_url}/mcp"
    return {
        "resource": resource,
        "authorization_servers": [config.oauth_issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["sporfie"],
    }


async def protected_resource_response(request: Request) -> Response:
    """Serve the protected-resource metadata (only mounted when OAuth is enabled)."""
    config = request.app.state.config
    return JSONResponse(protected_resource_metadata(config))


def mark_token_rejected(scope: MutableMapping[str, Any] | None) -> None:
    """Record on the request that the API rejected its bearer token (see the middleware)."""
    if isinstance(scope, MutableMapping):
        scope[TOKEN_REJECTED] = True


class OAuthChallengeMiddleware:
    """Spec-pure 401s for the MCP endpoint, pointing at the protected-resource metadata.

    * No usable ``Authorization: Bearer <token>`` header (none, another scheme, or more than one
      Authorization header, see auth.py): 401 with
      ``WWW-Authenticate: Bearer resource_metadata="…"``, the signal MCP clients use to discover
      the authorization server and begin the flow.
    * The request carried a token and the API rejected it (the tool layer marks the scope):
      the response is replaced by a 401 with ``error="invalid_token"``. Other failures, such as
      a token that is valid but not allowed to act on a company, stay ordinary tool errors.

    Health and discovery paths are exempt. The response is only replaced before it starts, which
    holds for this server's JSON (non-streaming) responses.
    """

    def __init__(self, app: ASGIApp, config) -> None:
        self.app = app
        self.config = config
        self.metadata_url = f"{config.public_url}/.well-known/oauth-protected-resource"

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.config.oauth_issuer:
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if any(path.startswith(prefix) for prefix in _UNCHALLENGED_PREFIXES):
            await self.app(scope, receive, send)
            return
        if not _has_bearer_token(scope):
            await self._challenge(send, error=None)
            return

        replaced = False

        async def send_or_challenge(message: Message) -> None:
            nonlocal replaced
            if message["type"] == "http.response.start" and scope.get(TOKEN_REJECTED):
                replaced = True
                await self._challenge(send, error="invalid_token")
                return
            if not replaced:
                await send(message)

        await self.app(scope, receive, send_or_challenge)

    async def _challenge(self, send: Send, error: str | None) -> None:
        if error:
            description = "The access token was rejected (expired or revoked)."
            www = (
                f'Bearer error="{error}", error_description="{description}", '
                f'resource_metadata="{self.metadata_url}"'
            )
            body = {"error": error, "error_description": description}
        else:
            www = f'Bearer resource_metadata="{self.metadata_url}"'
            body = {"error": "unauthorized", "error_description": "Authorization required."}
        payload = json.dumps(body).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 401,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(payload)).encode()),
                    (b"www-authenticate", www.encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": payload})


def _has_bearer_token(scope: Scope) -> bool:
    values = [value for name, value in scope.get("headers", []) if name == b"authorization"]
    # Several Authorization headers are ambiguous, so none of them counts as a credential.
    return len(values) == 1 and bearer_token(values[0].decode("latin-1")) is not None
