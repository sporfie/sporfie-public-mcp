"""MCP server for the Sporfie PUBLIC API, for external agents (public-facing).

A standalone **Streamable HTTP** service exposed on the internet (mcp.sporfie.com) so
customers' agents (Claude Code, the Claude API MCP connector, Cursor, …) can drive the Sporfie
public API with their own personal API token.

Auth model: per-request bearer passthrough, zero server-held credentials.
  * The MCP client sends ``Authorization: Bearer <token>``, where <token> is a personal API
    token created in Sporfie account settings (or an OAuth access token, see oauth.py).
  * Every tool forwards that credential to the Sporfie API's ``/public/**`` endpoints, which
    authenticate and authorize each request. This server grants nothing by itself. Exactly one
    Authorization header is accepted, and the scheme is matched case-insensitively (auth.py).
  * With OAuth off (the default) ``initialize`` / ``tools/list`` work without auth, so clients
    can connect and show the catalog, and a tool CALL without the header gets an error result
    with setup instructions. With OAuth on (production), oauth.py answers every MCP request
    that lacks a Bearer token with a 401 discovery challenge before it is dispatched, and
    ``tools/list`` is no exception.
  * The Help Center tools (``search_help_center`` & co.) never use the caller's credential,
    because published support articles are public. They sit behind the same challenge.

Tool arguments are untrusted input. Values that end up in a URL path are validated and
encoded (paths.py), and every failure is returned as an MCP tool error (``isError: true``),
never as a successful result.

Runs stateless (``stateless_http=True``) so replicas scale horizontally with no session
affinity; ``json_response=True`` keeps responses plain JSON, which suits load balancers and
proxies better than SSE. ASGI entrypoint: ``app`` (uvicorn ``sporfie_public_server.server:app``);
``/health`` is the load-balancer probe.
"""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import Icon, ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import __version__, paths
from .auth import bearer_token
from .client import (
    SporfieApiClient,
    SporfieApiError,
    SporfieApiHttpError,
    SporfieApiOverloaded,
)
from .client_ip import client_address, forwardable
from .config import load_config
from .help_center import HelpCenterClient
from .oauth import OAuthChallengeMiddleware, mark_token_rejected, protected_resource_response
from .rate_limit import RateLimitMiddleware

logger = logging.getLogger(__name__)

_CONFIG = load_config()

mcp = FastMCP(
    "sporfie-public-api",
    stateless_http=True,
    json_response=True,
    # Answered with 413 before the body is parsed. The SDK's 4 MiB default, times every call
    # admitted at once, is more than a pod holds; tool arguments are small JSON.
    max_request_body_size=_CONFIG.max_request_bytes,
    # Server logo, advertised in the initialize response (MCP spec 2025-11-25 icons metadata).
    # Clients MUST support PNG and SHOULD support SVG, so both are listed.
    website_url="https://www.sporfie.com",
    icons=[
        Icon(
            src="https://www.sporfie.com/sporfie-2024-logo-compact-dark.svg",
            mimeType="image/svg+xml",
            sizes=["any"],
        ),
        Icon(
            src="https://www.sporfie.com/favicon/default.png",
            mimeType="image/png",
            sizes=["32x32"],
        ),
    ],
    # Explicit DNS-rebinding settings: FastMCP's implicit default only allows localhost Hosts,
    # which would reject every request arriving via mcp.sporfie.com with a 421.
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=list(_CONFIG.allowed_hosts),
        allowed_origins=["https://mcp.sporfie.com"],
    ),
)
# FastMCP has no ``version`` argument (mcp<2), so ``initialize`` would report the MCP SDK's own
# version as serverInfo.version. Report this server's instead: it is how an operator, or
# SECURITY.md, tells which release is running.
mcp._mcp_server.version = __version__
_CLIENT = SporfieApiClient(
    _CONFIG.base_url,
    _CONFIG.timeout_s,
    _CONFIG.max_response_chars,
    max_response_bytes=_CONFIG.max_response_bytes,
    max_concurrency=_CONFIG.max_concurrent_upstream,
    max_queued=_CONFIG.max_queued_upstream,
    queue_timeout_s=_CONFIG.queue_timeout_s,
    deadline_s=_CONFIG.deadline_s,
)
# Help Center tools are anonymous (published articles are public): they never receive the
# caller's Authorization header or address.
_HC = HelpCenterClient(
    _CONFIG.help_center_base_url,
    _CONFIG.timeout_s,
    _CONFIG.max_response_chars,
    max_response_bytes=_CONFIG.max_response_bytes,
    max_concurrency=_CONFIG.max_concurrent_upstream,
    max_queued=_CONFIG.max_queued_upstream,
    queue_timeout_s=_CONFIG.queue_timeout_s,
    deadline_s=_CONFIG.deadline_s,
)

_MISSING_AUTH = (
    "No Authorization header reached the server. Configure your MCP client to send "
    "'Authorization: Bearer <your Sporfie API token>' with every request — in Claude Code: "
    "claude mcp add --transport http sporfie https://mcp.sporfie.com/mcp "
    '--header "Authorization: Bearer <token>". Tokens are created in Sporfie account '
    "settings (API tokens)."
)
_AMBIGUOUS_AUTH = (
    "The request carries more than one Authorization header, so it is unclear which credential "
    "is meant. Send exactly one Authorization header: 'Authorization: Bearer <your Sporfie API "
    "token>'."
)
_NOT_BEARER_AUTH = (
    "The Authorization header is not a Bearer credential. Send it as 'Authorization: Bearer "
    "<your Sporfie API token>': the word Bearer, one space, then the token."
)
_AUTH_REJECTED = (
    " The Sporfie API rejected the token: check that it is still valid (not revoked or "
    "expired) and reconnect with a fresh one."
)

# Error codes with which the Sporfie API rejects the token itself. A 401 with any other code
# (e.g. "Unauthorized": the token is fine but may not act on that company) is a plain tool error.
_TOKEN_REJECTED_CODES = frozenset({"invalid_bearer", "Invalid Authorization header"})

# Tool annotations (MCP spec): hints clients use to decide when to ask the user first. They
# describe behavior; the Sporfie API still authorizes every call.
_READ = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_CREATE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False
)
_OVERWRITE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
)
_REMOVE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=False
)
# Ends a running event by setting its end to "now". Repeating the call sets it to a new "now",
# so unlike a delete it is not idempotent, and clients should not retry it blindly.
_CLOSE = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False
)
# Registers a caller-chosen URL that Sporfie will then send event data to.
_WEBHOOK = ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=True, openWorldHint=True
)
_HELP = ToolAnnotations(readOnlyHint=True, openWorldHint=False)


def _request(ctx: Context) -> Any | None:
    """The Starlette request behind this tool call, or None outside an HTTP request."""
    try:
        return ctx.request_context.request
    except ValueError:  # tool invoked outside a request context
        return None


def _authorization(ctx: Context) -> str | None:
    """The caller's credential as ``Bearer <token>``, or None when there is none to forward.

    None means no HTTP request or an absent (or empty) header. A header the server will not
    forward raises ToolError instead: more than one Authorization header, since it is unclear
    which one is meant, or one that is not a Bearer credential. The scheme is matched
    case-insensitively but forwarded in canonical form (see auth.py).
    """
    request = _request(ctx)
    if request is None:
        return None
    values = request.headers.getlist("authorization")
    if len(values) > 1:
        raise ToolError(_AMBIGUOUS_AUTH)
    if not values or not values[0].strip():
        return None
    token = bearer_token(values[0])
    if token is None:
        raise ToolError(_NOT_BEARER_AUTH)
    return f"Bearer {token}"


def _client_ip(ctx: Context) -> str | None:
    """The caller's public address as seen by the trusted proxy, or None (then nothing is sent)."""
    request = _request(ctx)
    if request is None:
        return None
    headers = request.headers
    forwarded = headers.getlist("x-forwarded-for") if hasattr(headers, "getlist") else []
    client = getattr(request, "client", None)
    peer = client.host if client else None
    address = client_address(forwarded, peer, _CONFIG.trusted_proxy_hops)
    return address if forwardable(address) else None


async def _call(
    ctx: Context,
    method: str,
    path: str,
    params: dict[str, Any] | None = None,
    json_body: Any | None = None,
) -> str:
    """One Sporfie API call on behalf of the caller. Failures raise ToolError (isError)."""
    authorization = _authorization(ctx)
    if not authorization:
        raise ToolError(_MISSING_AUTH)
    try:
        return await _CLIENT.request(
            method,
            path,
            authorization,
            params=params,
            json_body=json_body,
            client_ip=_client_ip(ctx),
        )
    except SporfieApiHttpError as exc:
        hint = ""
        if exc.status == 401 and exc.code in _TOKEN_REJECTED_CODES:
            # With OAuth on, this becomes an HTTP 401 invalid_token challenge (oauth.py), so the
            # client refreshes its token. Without OAuth the tool error below is the answer.
            mark_token_rejected(getattr(_request(ctx), "scope", None))
            hint = _AUTH_REJECTED
        raise ToolError(f"{exc}{hint}") from exc
    except SporfieApiOverloaded as exc:
        # This server shed the call; the API said nothing, least of all about the token.
        raise ToolError(str(exc)) from exc
    except SporfieApiError as exc:
        raise ToolError(f"Sporfie API unreachable: {exc}") from exc


def _event_path(template: str, event_key_or_external_id: str) -> str:
    return paths.build_path(template, event_key_or_external_id=event_key_or_external_id)


# ----- events -----


@mcp.tool(title="Get event", annotations=_READ)
async def get_event(event_key_or_external_id: str, ctx: Context) -> str:
    """Get the public projection of one Sporfie event (name, teams, sport, times,
    state, streaming/clip info) by its Sporfie eventKey or by the externalID it
    was created with through the public API."""
    return await _call(ctx, "GET", _event_path("/public/events/{}", event_key_or_external_id))


@mcp.tool(title="Create event", annotations=_CREATE)
async def create_event(external_id: str, event: dict[str, Any], ctx: Context) -> str:
    """Create a Sporfie event. external_id is YOUR stable identifier for it (letters,
    digits, '-' and '_', at most 64 characters); later calls may address the event by it.

    The event object supports: companyKey (required — a company your token may
    manage), name, description, sport (see list_sports), placeKey (bind to a
    camera-equipped place), scheduledStartTime/scheduledEndTime/announcedTime/
    announcedDuration/startTime (epoch millis), homeTeam, awayTeam, location
    ({name, geoLoc:{lat,lng}}), thumbnailURL, pinCode, cameraPinCode,
    notSearchable, metadata (small object), disableSporfieWatermark.
    Example: {"companyKey": "c1", "name": "U19 final", "sport": "football",
    "homeTeam": "T1", "awayTeam": "T2"}. Returns the created eventKey (HTTP 201)."""
    path = paths.build_path("/public/events/{}", external_id=external_id)
    return await _call(ctx, "POST", path, json_body=event)


@mcp.tool(title="Update event", annotations=_OVERWRITE)
async def update_event(event_key_or_external_id: str, patch: dict[str, Any], ctx: Context) -> str:
    """Update fields of an existing event (PATCH semantics — only the submitted
    fields change). Same field names as create_event."""
    path = _event_path("/public/events/{}", event_key_or_external_id)
    return await _call(ctx, "PATCH", path, json_body=patch)


@mcp.tool(title="Close event", annotations=_CLOSE)
async def close_event(event_key_or_external_id: str, ctx: Context) -> str:
    """Close (terminate) a running event now: sets its end to now and stops
    recording/streaming. Only works for events created by the same API system
    that is calling. Repeating the call re-sets the end time to the new "now"."""
    path = _event_path("/public/events/{}/close", event_key_or_external_id)
    return await _call(ctx, "POST", path)


@mcp.tool(title="Delete event", annotations=_REMOVE)
async def delete_event(event_key_or_external_id: str, ctx: Context) -> str:
    """Permanently delete an event. Irreversible — prefer close_event to merely
    end a running event."""
    path = _event_path("/public/events/{}", event_key_or_external_id)
    return await _call(ctx, "DELETE", path)


# ----- discovery -----


@mcp.tool(title="Search a company's events", annotations=_READ)
async def search_events(
    company_key: str,
    ctx: Context,
    state: str = "current",
    page_size: int = 20,
    page: int = 0,
) -> str:
    """List a company's events by state: 'future' (scheduled), 'current'
    (running now), or 'past' (finished). Paged (page_size 1-100) — raise page
    for more results."""
    if state not in ("future", "current", "past"):
        raise ToolError("Invalid state — use one of: future, current, past.")
    params = {
        "companyKey": company_key,
        "state": state,
        "pageSize": paths.bounded_int(page_size, "page_size", 1, 100),
        "page": paths.bounded_int(page, "page", 0, 10_000),
    }
    return await _call(ctx, "GET", "/public/event-search-by-company", params=params)


@mcp.tool(title="Find the event live on a place at a time", annotations=_READ)
async def lookup_event_by_place_and_time(
    place_key: str, year: int, month: int, day: int, hour: int, ctx: Context
) -> str:
    """Find the event that was live on a given place (venue/camera location)
    at a given local date + hour. 404 means no event covered that hour."""
    return await _call(
        ctx,
        "GET",
        "/public/event-lookup-by-place-and-time",
        params={"placeKey": place_key, "year": year, "month": month, "day": day, "hour": hour},
    )


@mcp.tool(title="Get a place's live event", annotations=_READ)
async def get_active_event_key(place_key: str, ctx: Context) -> str:
    """The eventKey currently live on a place, if any (404 = nothing live)."""
    path = paths.build_path("/public/places/{}/activeEventKey", place_key=place_key)
    return await _call(ctx, "GET", path)


@mcp.tool(title="List a company's places", annotations=_READ)
async def list_places(company_key: str, ctx: Context) -> str:
    """List a company's places (venues/camera locations) with their keys —
    the placeKeys used by create_event, lookup and live-event tools. Accepts
    the company key or its public slug."""
    return await _call(ctx, "GET", "/public/places", params={"companyKey": company_key})


@mcp.tool(title="List sports", annotations=_READ)
async def list_sports(ctx: Context) -> str:
    """The sport identifiers Sporfie knows (valid values for events' 'sport')."""
    return await _call(ctx, "GET", "/public/sports")


# ----- moments (highlight clips) -----


@mcp.tool(title="Register a highlight click", annotations=_CREATE)
async def register_click(
    event_key_or_external_id: str,
    timestamp_ms: int,
    ctx: Context,
    metadata: dict[str, Any] | None = None,
) -> str:
    """Register a 'click' at an absolute timestamp (epoch millis) inside an
    event — Sporfie cuts a highlight clip (a 'moment') around it. Optional
    small metadata object is stored on the moment. Returns the momentKey."""
    body: dict[str, Any] = {"timeStamp": timestamp_ms}
    if metadata is not None:
        body["metadata"] = metadata
    path = _event_path("/public/events/{}/clicks", event_key_or_external_id)
    return await _call(ctx, "POST", path, json_body=body)


@mcp.tool(title="Get moment", annotations=_READ)
async def get_moment(moment_key: str, ctx: Context) -> str:
    """Get one moment (highlight clip): its event, timing, video URLs, metadata."""
    path = paths.build_path("/public/moments/{}", moment_key=moment_key)
    return await _call(ctx, "GET", path)


@mcp.tool(title="Update moment", annotations=_OVERWRITE)
async def update_moment(moment_key: str, patch: dict[str, Any], ctx: Context) -> str:
    """Update a moment (PATCH semantics), e.g. {"metadata": {...}} to replace
    the metadata stored by register_click."""
    path = paths.build_path("/public/moments/{}", moment_key=moment_key)
    return await _call(ctx, "PATCH", path, json_body=patch)


@mcp.tool(title="Delete moment", annotations=_REMOVE)
async def delete_moment(moment_key: str, ctx: Context) -> str:
    """Permanently delete a moment (highlight clip). Irreversible."""
    path = paths.build_path("/public/moments/{}", moment_key=moment_key)
    return await _call(ctx, "DELETE", path)


# ----- webhooks -----


@mcp.tool(title="Watch event (webhook)", annotations=_WEBHOOK)
async def watch_event(event_key_or_external_id: str, webhook_url: str, ctx: Context) -> str:
    """Subscribe a webhook to an event: Sporfie POSTs event lifecycle/content
    updates to the URL (HTTPS). One watch per event per API system — calling
    again replaces it."""
    path = _event_path("/public/events/{}/watch", event_key_or_external_id)
    return await _call(ctx, "PUT", path, json_body={"url": webhook_url})


@mcp.tool(title="Stop watching event", annotations=_REMOVE)
async def unwatch_event(event_key_or_external_id: str, ctx: Context) -> str:
    """Remove this API system's webhook subscription from an event."""
    path = _event_path("/public/events/{}/watch", event_key_or_external_id)
    return await _call(ctx, "DELETE", path)


# ----- support / Help Center (public articles: the caller's credential is never used) -----


async def _help_center(call) -> str:
    try:
        return await call
    except SporfieApiHttpError as exc:
        raise ToolError(f"Help Center error: {exc}") from exc
    except SporfieApiOverloaded as exc:
        raise ToolError(str(exc)) from exc
    except SporfieApiError as exc:
        raise ToolError(f"Help Center unreachable: {exc}") from exc


@mcp.tool(title="Search the Help Center", annotations=_HELP)
async def search_help_center(query: str, locale: str = "en-us", page: int = 1) -> str:
    """Search Sporfie's support Help Center (sporfie.zendesk.com) for how-tos,
    troubleshooting and known issues — e.g. camera setup, streaming problems,
    account questions. Needs no Sporfie permissions. Returns matching articles
    with ids and public URLs; follow up with get_help_article."""
    return await _help_center(_HC.search(query, locale, page))


@mcp.tool(title="Read a Help Center article", annotations=_HELP)
async def get_help_article(article_id: int, locale: str = "en-us") -> str:
    """Read one Help Center article in full (plain text) by the id returned
    from search_help_center. Includes the public URL to share with the user."""
    return await _help_center(_HC.article(article_id, locale))


@mcp.tool(title="Browse Help Center sections", annotations=_HELP)
async def list_help_center_sections(locale: str = "en-us") -> str:
    """Browse the Help Center's category/section tree — useful to discover what
    support topics exist before searching."""
    return await _help_center(_HC.sections(locale))


# ----- ASGI wiring -----


async def _health(_: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "sporfie-public-api-mcp"})


app = mcp.streamable_http_app()
app.state.config = _CONFIG
app.router.routes.append(Route("/health", endpoint=_health, methods=["GET"]))

# OAuth 2.1 resource-server surface (RFC 9728 / MCP auth spec). Both pieces are inert unless
# SPORFIE_MCP_OAUTH_ISSUER is set, so the manual bearer-header path is unaffected until then.
if _CONFIG.oauth_issuer:
    app.router.routes.append(
        Route(
            "/.well-known/oauth-protected-resource",
            endpoint=protected_resource_response,
            methods=["GET"],
        )
    )
    # Some clients probe the resource-path-suffixed variant.
    app.router.routes.append(
        Route(
            "/.well-known/oauth-protected-resource/mcp",
            endpoint=protected_resource_response,
            methods=["GET"],
        )
    )
    # Spec-pure challenge: unauthenticated MCP requests get 401 + WWW-Authenticate so clients
    # discover the AS. The rate limiter is added after this, so it wraps outermost and runs
    # first — unauthenticated challenge traffic is itself rate-limited, which is what we want.
    app.add_middleware(OAuthChallengeMiddleware, config=_CONFIG)

# Hammering backstop per client address, /health exempt (see rate_limit.py).
app.add_middleware(
    RateLimitMiddleware,
    limit_per_minute=_CONFIG.rate_limit_per_minute,
    trusted_proxy_hops=_CONFIG.trusted_proxy_hops,
)


if __name__ == "__main__":  # local dev convenience: python -m sporfie_public_server.server
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)
