"""OAuth 2.1 from the client's side: what Cursor does when it connects to the server.

Discovery (RFC 9728, RFC 8414), dynamic client registration (RFC 7591), the authorization-code
flow with PKCE (RFC 7636) and a resource indicator (RFC 8707), then refresh. The one step that
needs a person is approving the consent screen; everything else is plain HTTP. Token values are
never printed.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import queue
import re
import secrets
import tempfile
import threading
import time
import webbrowser
from collections.abc import Callable
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Self
from urllib.parse import parse_qsl, urlencode, urlsplit

import httpx

SCOPE = "sporfie"
CLIENT_NAME = "Sporfie MCP e2e"
REFRESH_MARGIN_S = (
    900  # refresh a stored access token with less than this left: a run takes minutes
)
MCP_ACCEPT = {"Accept": "application/json, text/event-stream"}


class OAuthFlowError(RuntimeError):
    """A step of the flow failed. The message says which, and what to do about it."""


# ---------------------------------------------------------------- discovery


_PARAMETER = re.compile(r'([A-Za-z_][\w-]*)="((?:[^"\\]|\\.)*)"')


def parse_challenge(header: str) -> dict[str, str]:
    """The parameters of a ``WWW-Authenticate: Bearer ...`` header (empty for another scheme)."""
    scheme, _, rest = header.strip().partition(" ")
    if scheme.lower() != "bearer":
        return {}
    return dict(_PARAMETER.findall(rest))


@dataclass(frozen=True)
class Discovery:
    resource: str  # the canonical URI of the MCP server: what a token is bound to
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: str


def initialize_request() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "sporfie-mcp-e2e", "version": "0"},
        },
    }


def discover(mcp_url: str, http: httpx.Client) -> Discovery:
    """Follow the path a client takes from a bare MCP URL to the authorization server."""
    challenge = http.post(mcp_url, json=initialize_request(), headers=MCP_ACCEPT)
    if challenge.status_code != 401:
        raise OAuthFlowError(
            f"{mcp_url} answered an unauthenticated request with HTTP {challenge.status_code}, "
            "not a 401 challenge: is OAuth enabled on this server?"
        )
    metadata_url = parse_challenge(challenge.headers.get("www-authenticate", "")).get(
        "resource_metadata"
    )
    if not metadata_url:
        raise OAuthFlowError("the 401 challenge names no resource_metadata URL")
    resource_metadata = _get_json(http, metadata_url)
    servers = resource_metadata.get("authorization_servers") or []
    if not servers:
        raise OAuthFlowError(f"{metadata_url} lists no authorization server")
    issuer = str(servers[0]).rstrip("/")
    server_metadata = _get_json(http, f"{issuer}/.well-known/oauth-authorization-server")
    try:
        return Discovery(
            resource=str(resource_metadata["resource"]),
            issuer=str(server_metadata["issuer"]),
            authorization_endpoint=str(server_metadata["authorization_endpoint"]),
            token_endpoint=str(server_metadata["token_endpoint"]),
            registration_endpoint=str(server_metadata["registration_endpoint"]),
        )
    except KeyError as missing:
        raise OAuthFlowError(f"the authorization server metadata lacks {missing}") from None


def _get_json(http: httpx.Client, url: str) -> dict[str, Any]:
    response = http.get(url)
    if response.status_code != 200:
        raise OAuthFlowError(f"GET {url} answered HTTP {response.status_code}")
    return response.json()


# ---------------------------------------------------------------- registration and authorization


def register(
    http: httpx.Client,
    discovery: Discovery,
    redirect_uris: list[str],
    client_name: str = CLIENT_NAME,
) -> httpx.Response:
    """Dynamic client registration. The raw response: a test may want the refusal."""
    return http.post(
        discovery.registration_endpoint,
        json={
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
        },
    )


@dataclass(frozen=True)
class Pkce:
    verifier: str
    challenge: str

    @classmethod
    def new(cls) -> Pkce:
        verifier = secrets.token_urlsafe(48)
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        return cls(verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii"))


def authorize_url(
    discovery: Discovery, client_id: str, redirect_uri: str, pkce: Pkce, state: str
) -> str:
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
            "state": state,
            "scope": SCOPE,
            "resource": discovery.resource,
        }
    )
    return f"{discovery.authorization_endpoint}?{query}"


class CallbackServer:
    """The loopback listener a desktop client redirects the browser back to."""

    def __init__(self, port: int) -> None:
        arrivals: queue.Queue[dict[str, str]] = queue.Queue()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parts = urlsplit(self.path)
                if parts.path != "/callback":
                    self.send_response(404)
                    self.end_headers()
                    return
                arrivals.put(dict(parse_qsl(parts.query)))
                body = b"<h3>Sporfie MCP e2e: approved.</h3>You can close this tab."
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self._arrivals = arrivals
        self._server = HTTPServer(("127.0.0.1", port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return self._server.server_address[1]

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    def wait_for(self, state: str, timeout_s: float) -> dict[str, str]:
        """The callback carrying ``state``. One from an older, abandoned link is not ours: skip it."""
        deadline = time.monotonic() + timeout_s
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise OAuthFlowError(f"no approval arrived within {int(timeout_s)} s")
            try:
                arrived = self._arrivals.get(timeout=left)
            except queue.Empty:
                continue
            if arrived.get("state") == state:
                return arrived


def redirect_uri_for(port: int) -> str:
    return f"http://localhost:{port}/callback"


def token_request(
    http: httpx.Client, discovery: Discovery, fields: dict[str, str]
) -> httpx.Response:
    return http.post(discovery.token_endpoint, data=fields)


def authenticate(
    http: httpx.Client,
    discovery: Discovery,
    client_id: str,
    *,
    port: int,
    timeout_s: float = 600,
    announce: Callable[[str], None] = print,
    open_browser: bool = True,
) -> dict[str, Any]:
    """Authorization code + PKCE through the browser. Returns the token response."""
    redirect_uri = redirect_uri_for(port)
    pkce, state = Pkce.new(), secrets.token_urlsafe(16)
    url = authorize_url(discovery, client_id, redirect_uri, pkce, state)
    with CallbackServer(port) as callback:
        announce(
            f"Approve the connection in your browser (waiting up to {int(timeout_s)} s):\n{url}"
        )
        if open_browser:
            webbrowser.open(url)
        arrived = callback.wait_for(state, timeout_s)
    if "error" in arrived or "code" not in arrived:
        detail = arrived.get("error_description", "")
        raise OAuthFlowError(f"authorization refused: {arrived.get('error', 'no code')} {detail}")
    response = token_request(
        http,
        discovery,
        {
            "grant_type": "authorization_code",
            "code": arrived["code"],
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_verifier": pkce.verifier,
            "resource": discovery.resource,
        },
    )
    if response.status_code != 200:
        raise OAuthFlowError(
            f"token exchange failed: HTTP {response.status_code} {response.text[:200]}"
        )
    return response.json()


# ---------------------------------------------------------------- tokens


def jwt_claims(token: str) -> dict[str, Any]:
    """The claims of a JWT, unverified: for reading audience and expiry, never for trust."""
    try:
        payload = token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return {}


@dataclass
class Grant:
    client_id: str
    access_token: str
    refresh_token: str
    expires_at: float
    resource: str
    issuer: str

    @classmethod
    def from_token_response(
        cls, body: dict[str, Any], client_id: str, discovery: Discovery, now: float | None = None
    ) -> Grant:
        now = time.time() if now is None else now
        return cls(
            client_id=client_id,
            access_token=body["access_token"],
            refresh_token=body["refresh_token"],
            expires_at=now + float(body.get("expires_in", 3600)),
            resource=discovery.resource,
            issuer=discovery.issuer,
        )

    def needs_refresh(self, now: float | None = None) -> bool:
        return self.expires_at - (time.time() if now is None else now) < REFRESH_MARGIN_S


def refresh_grant(http: httpx.Client, discovery: Discovery, grant: Grant) -> Grant:
    """Trade the refresh token for a new pair. The old refresh token stops working."""
    response = token_request(
        http,
        discovery,
        {
            "grant_type": "refresh_token",
            "refresh_token": grant.refresh_token,
            "client_id": grant.client_id,
            "resource": discovery.resource,
        },
    )
    if response.status_code != 200:
        raise OAuthFlowError(
            f"the stored grant cannot be refreshed (HTTP {response.status_code}). "
            "Sign in again: python -m e2e.login"
        )
    return Grant.from_token_response(response.json(), grant.client_id, discovery)


class TokenStore:
    """One JSON file, readable by its owner only: the registered client and the current grant."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _read(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text())
        except (FileNotFoundError, ValueError):
            return {}

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=".e2e-")
        try:
            with os.fdopen(handle, "w") as out:
                json.dump(data, out)
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)
            raise

    def client_id(self, issuer: str, redirect_uri: str) -> str | None:
        client = self._read().get("client") or {}
        if client.get("issuer") == issuer and redirect_uri in client.get("redirect_uris", []):
            return client.get("client_id")
        return None

    def put_client(self, issuer: str, client_id: str, redirect_uris: list[str]) -> None:
        data = self._read()
        data["client"] = {"issuer": issuer, "client_id": client_id, "redirect_uris": redirect_uris}
        self._write(data)

    def grant(self) -> Grant | None:
        stored = self._read().get("grant")
        try:
            return Grant(**stored) if stored else None
        except TypeError:
            return None

    def put_grant(self, grant: Grant) -> None:
        data = self._read()
        data["grant"] = asdict(grant)
        self._write(data)

    def access_token(self, http: httpx.Client, discovery: Discovery) -> str | None:
        """A usable access token, refreshed (and the new pair kept) when it is about to expire."""
        grant = self.grant()
        if grant is None:
            return None
        if grant.needs_refresh():
            grant = refresh_grant(http, discovery, grant)
            self.put_grant(grant)
        return grant.access_token


def sign_in(
    http: httpx.Client,
    discovery: Discovery,
    store: TokenStore,
    *,
    port: int,
    timeout_s: float = 600,
    announce: Callable[[str], None] = print,
    open_browser: bool = True,
) -> Grant:
    """Register once per environment, then approve in the browser; keeps the grant in ``store``."""
    redirect_uri = redirect_uri_for(port)
    client_id = store.client_id(discovery.issuer, redirect_uri)
    if client_id is None:
        registration = register(http, discovery, [redirect_uri])
        if registration.status_code != 201:
            raise OAuthFlowError(
                f"client registration failed: HTTP {registration.status_code} {registration.text[:200]}"
            )
        client_id = registration.json()["client_id"]
        store.put_client(discovery.issuer, client_id, [redirect_uri])
    tokens = authenticate(
        http,
        discovery,
        client_id,
        port=port,
        timeout_s=timeout_s,
        announce=announce,
        open_browser=open_browser,
    )
    grant = Grant.from_token_response(tokens, client_id, discovery)
    store.put_grant(grant)
    return grant


def summary(grant: Grant) -> dict[str, Any]:
    """What may be shown about a grant: no token value."""
    claims = jwt_claims(grant.access_token)
    return {
        "audience": claims.get("aud"),
        "access_token_valid_for_s": int(grant.expires_at - time.time()),
        "has_refresh_token": bool(grant.refresh_token),
        "resource": grant.resource,
    }
