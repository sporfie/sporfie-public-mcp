"""Raw JSON-RPC over HTTP, for the tests that must see the HTTP layer the MCP client hides."""

from __future__ import annotations

from typing import Any

import httpx

from .oauth import MCP_ACCEPT, initialize_request

# Long enough to look like a real (JWT) token: a proxy in front of the API may refuse a short one.
MADE_UP_TOKEN = "made-up." + "x" * 400


def tool_call(name: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments or {}},
    }


def post(
    http: httpx.Client, url: str, body: dict[str, Any] | None = None, token: str | None = None
) -> httpx.Response:
    """POST one JSON-RPC message (``initialize`` by default), with a bearer token if given."""
    headers = dict(MCP_ACCEPT)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return http.post(url, json=body if body is not None else initialize_request(), headers=headers)
