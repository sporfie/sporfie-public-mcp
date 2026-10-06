"""A synchronous handle on one MCP session, so a test reads like a script.

The official client runs on its own event loop in a background thread. One task opens the session
and closes it, so the SDK's cancel scopes are entered and left in the same place, and every tool
call is handed to that loop from the test's thread.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import json
import re
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import InitializeResult, Tool

CALL_TIMEOUT_S = 120

# The text of an upstream failure: "HTTP 404: {...}", possibly behind the SDK's own prefix.
_HTTP_FAILURE = re.compile(r"\bHTTP (\d{3}):")


@dataclass(frozen=True)
class ToolResult:
    name: str
    arguments: dict[str, Any]
    text: str
    is_error: bool

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except ValueError as exc:
            raise AssertionError(f"{self.name} did not return JSON: {self.text[:200]!r}") from exc

    @property
    def http_status(self) -> int | None:
        """The upstream status this result reports, if its text reports one."""
        found = _HTTP_FAILURE.search(self.text[:120])
        return int(found.group(1)) if found else None

    @property
    def unflagged_failure(self) -> bool:
        """A failure reported as an ordinary result: an agent could not tell it from success."""
        status = self.http_status
        return status is not None and status >= 400 and not self.is_error

    def brief(self, limit: int = 160) -> str:
        shown = self.text.replace("\n", " ")
        return shown if len(shown) <= limit else f"{shown[:limit]} … (+{len(self.text) - limit})"


class McpClient:
    """One initialized session against ``url`` with ``token``, paced to respect rate limits."""

    def __init__(self, url: str, token: str, min_interval_s: float = 1.15) -> None:
        self._url = url
        self._headers = {"Authorization": f"Bearer {token}"}
        self._min_interval_s = min_interval_s
        self._last_call = 0.0
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._session: ClientSession | None = None
        self._initialized: InitializeResult | None = None
        self._ready: concurrent.futures.Future[None] = concurrent.futures.Future()
        self._stop: asyncio.Event | None = None
        self._runner: concurrent.futures.Future[None] | None = None
        self.results: list[ToolResult] = []

    # -- lifecycle

    def start(self) -> McpClient:
        self._thread.start()
        self._runner = asyncio.run_coroutine_threadsafe(self._serve(), self._loop)
        try:
            self._ready.result(timeout=CALL_TIMEOUT_S)
        except BaseException:
            self.stop()
            raise
        return self

    def stop(self) -> None:
        if self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._runner is not None:
            # A transport that failed to start was already reported by start().
            with contextlib.suppress(Exception):
                self._runner.result(timeout=30)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=10)

    async def _serve(self) -> None:
        self._stop = asyncio.Event()
        try:
            async with (
                httpx.AsyncClient(
                    headers=self._headers,
                    timeout=httpx.Timeout(30, read=300),
                    follow_redirects=True,
                ) as http_client,
                streamable_http_client(self._url, http_client=http_client) as (read, write, _),
                ClientSession(
                    read, write, read_timeout_seconds=timedelta(seconds=CALL_TIMEOUT_S)
                ) as session,
            ):
                self._initialized = await session.initialize()
                self._session = session
                self._ready.set_result(None)
                await self._stop.wait()
        except BaseException as failure:
            if not self._ready.done():
                self._ready.set_exception(failure)
            else:
                raise

    def _run(self, coroutine: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coroutine, self._loop).result(CALL_TIMEOUT_S + 10)

    # -- what the server says about itself

    @property
    def initialized(self) -> InitializeResult:
        assert self._initialized is not None, "start() the client first"
        return self._initialized

    def list_tools(self) -> list[Tool]:
        assert self._session is not None, "start() the client first"
        return list(self._run(self._session.list_tools()).tools)

    # -- tool calls

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> ToolResult:
        """Call one tool. Never raises for a tool failure: the result says whether it failed."""
        assert self._session is not None, "start() the client first"
        arguments = arguments or {}
        pause = self._min_interval_s - (time.monotonic() - self._last_call)
        if pause > 0:
            time.sleep(pause)
        self._last_call = time.monotonic()
        try:
            raw = self._run(self._session.call_tool(name, arguments))
            text = "\n".join(getattr(part, "text", "") for part in raw.content)
            result = ToolResult(name, arguments, text, bool(raw.isError))
        except Exception as failure:  # noqa: BLE001 - a transport failure, for example an HTTP 401
            result = ToolResult(name, arguments, f"{type(failure).__name__}: {failure}", True)
        self.results.append(result)
        return result
