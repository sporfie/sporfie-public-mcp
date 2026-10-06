"""Anonymous read-only client for the Sporfie Zendesk Help Center.

Published Help Center articles (https://sporfie.zendesk.com/hc/en-us) are readable through
Zendesk's anonymous API: no token and no secret, so these tools keep the server credential-less.
Read-only by construction: only search / article / section GETs exist.

HTML is stripped to plain text, and article bodies are capped with a truncation marker plus
the article's public URL so the agent can hand the full version to the user. Requests get the
same path verification and the same capped, uncompressed, deadline-bound reads as the Sporfie
API client.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from . import paths
from .client import (
    UPSTREAM_HEADERS,
    SporfieApiHttpError,
    UpstreamGate,
    ensure_request_target,
    send_capped,
)
from .error_body import render_error_body
from .text import strip_html

__all__ = ["HelpCenterClient", "strip_html"]


class HelpCenterClient:
    def __init__(
        self,
        base_url: str,
        timeout_s: float,
        max_response_chars: int,
        transport: httpx.AsyncBaseTransport | None = None,
        max_response_bytes: int = 2 * 1024 * 1024,
        max_concurrency: int = 32,
        max_queued: int = 64,
        queue_timeout_s: float = 5.0,
        deadline_s: float = 45.0,
    ) -> None:
        self._max_chars = max_response_chars
        self._max_bytes = max_response_bytes
        self._gate = UpstreamGate("Help Center", max_concurrency, max_queued, queue_timeout_s)
        self._deadline_s = deadline_s
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=timeout_s,
            transport=transport,
            headers=UPSTREAM_HEADERS,
        )

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """One anonymous GET, decoded JSON on success, SporfieApiError otherwise."""
        request = self._client.build_request("GET", path, params=params)
        ensure_request_target(self._client, request, path)
        status, text, truncated = await send_capped(
            self._client, request, self._gate, self._max_bytes, self._deadline_s
        )
        if not 200 <= status < 300:
            raise SporfieApiHttpError(status, render_error_body(text, status, "The Help Center"))
        if truncated:
            raise SporfieApiHttpError(
                status, "The Help Center response was too large to read; narrow the request."
            )
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise SporfieApiHttpError(
                status, "The Help Center returned an unreadable response."
            ) from exc
        if not isinstance(data, dict):
            raise SporfieApiHttpError(status, "The Help Center returned an unexpected response.")
        return data

    async def search(self, query: str, locale: str, page: int) -> str:
        data = await self._get(
            "/api/v2/help_center/articles/search.json",
            params={
                "query": query,
                "locale": paths.locale(locale),
                "per_page": 10,
                "page": paths.bounded_int(page, "page", 1, 1000),
            },
        )
        results = data.get("results", [])
        if not results:
            return f"No Help Center articles match '{query}'."
        count = data.get("count", len(results))
        page_count = data.get("page_count", "?")
        lines = [f"{count} article(s), page {data.get('page', page)}/{page_count}:"]
        for article in results:
            snippet = strip_html(article.get("snippet") or "").replace("\n", " ")
            lines.append(
                f"- [{article.get('id')}] {article.get('title', '(untitled)')} — {snippet}"
            )
            lines.append(f"  {article.get('html_url', '')}")
        lines.append("Use get_help_article(article_id) for a full article.")
        return "\n".join(lines)

    async def article(self, article_id: int, locale: str) -> str:
        article_id = paths.bounded_int(article_id, "article_id", 1, 10**15)
        path = paths.build_path(
            "/api/v2/help_center/{}/articles/{}.json",
            locale=paths.locale(locale),
            article_id=str(article_id),
        )
        article = (await self._get(path)).get("article", {})
        body = strip_html(article.get("body") or "")
        if len(body) > self._max_chars:
            body = (
                body[: self._max_chars] + "\n… [truncated — the full article is at the URL below]"
            )
        title = article.get("title", "(untitled)")
        return f"# {title}\n\n{body}\n\nPublic URL: {article.get('html_url', '')}"

    async def sections(self, locale: str) -> str:
        locale = paths.locale(locale)
        categories = await self._get(
            paths.build_path("/api/v2/help_center/{}/categories.json", locale=locale),
            params={"per_page": 100},
        )
        sections = await self._get(
            paths.build_path("/api/v2/help_center/{}/sections.json", locale=locale),
            params={"per_page": 100},
        )
        category_names = {c.get("id"): c.get("name", "?") for c in categories.get("categories", [])}
        lines = ["Help Center sections (browse; use search_help_center for content):"]
        for section in sections.get("sections", []):
            category = category_names.get(section.get("category_id"), "?")
            lines.append(f"- [{section.get('id')}] {category} / {section.get('name', '?')}")
        return "\n".join(lines)
