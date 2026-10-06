"""Thin async HTTP client for the Sporfie API's /public endpoints.

Credential-less by design: every call takes the caller's own ``Authorization`` header value
and forwards it unchanged. The Sporfie API authenticates and authorizes every request itself;
this client adds no authority.

Safety rails on every call:
  * the request is refused unless the path and host httpx is about to send are exactly the
    ones the tool built (see paths.py);
  * a compressed response is refused and never decoded: the request asks for ``identity`` and
    the body is read raw, so a few KiB on the wire cannot expand into gigabytes of memory;
  * the response body is read as a stream and abandoned past ``max_response_bytes``, and a call
    has a total ``deadline_s`` however slowly the upstream trickles bytes;
  * admission is bounded: at most ``max_concurrency`` requests are in flight per client, at
    most ``max_queued`` more wait for a slot, and none waits longer than ``queue_timeout_s``;
  * error bodies reach an agent only as an allowlist of safe fields, never raw (error_body.py).

Successful responses come back as compact JSON text, truncated at ``max_response_chars``.
Non-2xx answers raise ``SporfieApiHttpError``; transport failures raise ``SporfieApiUnreachable``.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from typing import Any, NoReturn

import httpx

from . import __version__
from .error_body import error_code, render_error_body

logger = logging.getLogger(__name__)

USER_AGENT = f"sporfie-public-mcp/{__version__}"

# Sent by every upstream client. ``Accept-Encoding: identity`` replaces httpx's default
# (gzip, deflate, ...): this server never wants a compressed body (see ``send_capped``).
UPSTREAM_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json",
    "Accept-Encoding": "identity",
}

_BUSY = "The server is busy; retry shortly."

_TRUNCATION_MARKER = (
    "\n… [truncated — narrow the query (smaller pageSize, a specific key) for the rest]"
)


class SporfieApiError(Exception):
    """A Sporfie API call did not produce a successful response."""


class SporfieApiUnreachable(SporfieApiError):
    """Transport-level failure (DNS, timeout, connection refused). Details are only logged."""


class SporfieApiOverloaded(SporfieApiError):
    """This server shed the call: no upstream slot came free in time. Retrying shortly is fine.

    Not an answer from the API, so it is never a token rejection.
    """


class SporfieApiHttpError(SporfieApiError):
    """The API answered with a non-2xx status. ``body`` is already sanitized for display.

    ``code`` is the machine-readable error code from a JSON error body (``code`` or ``error``),
    e.g. ``invalid_bearer`` when the API rejected the token itself.
    """

    def __init__(self, status: int, body: str, code: str | None = None) -> None:
        super().__init__(f"HTTP {status}: {body or '(no body)'}")
        self.status = status
        self.body = body
        self.code = code


class UpstreamGate:
    """Bounded admission to one upstream: ``max_concurrency`` calls run at once, at most
    ``max_queued`` more may wait for a slot, and none waits longer than ``queue_timeout_s``.

    A bare semaphore lets waiters pile up without limit, each one pinning a caller's connection
    and request memory. Past these limits a call fails at once (``SporfieApiOverloaded``), so
    load is shed instead of queued forever.
    """

    def __init__(
        self, name: str, max_concurrency: int, max_queued: int, queue_timeout_s: float
    ) -> None:
        self.name = name  # which upstream, for the log line when a call is shed
        self._slots = asyncio.Semaphore(max_concurrency)
        self._max_queued = max_queued
        self._queue_timeout_s = queue_timeout_s
        self.waiting = 0  # calls queued for a slot right now

    @contextlib.asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        """Hold one upstream slot for the duration of the block."""
        await self._acquire()
        try:
            yield
        finally:
            self._slots.release()

    async def _acquire(self) -> None:
        if not self._slots.locked():
            await self._slots.acquire()  # a slot is free right now: this never waits
            return
        if self.waiting >= self._max_queued:
            self._shed("queue full")
        self.waiting += 1
        try:
            async with asyncio.timeout(self._queue_timeout_s):
                await self._slots.acquire()
        except TimeoutError:
            self._shed(f"no slot within {self._queue_timeout_s}s")
        finally:
            self.waiting -= 1

    def _shed(self, reason: str) -> NoReturn:
        # Shedding is invisible to the operator otherwise: the caller just sees "busy".
        logger.warning(
            "%s is saturated (%s, %d waiting): call shed", self.name, reason, self.waiting
        )
        raise SporfieApiOverloaded(_BUSY) from None


class SporfieApiClient:
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
        self._max_response_chars = max_response_chars
        self._max_response_bytes = max_response_bytes
        self._gate = UpstreamGate("Sporfie API", max_concurrency, max_queued, queue_timeout_s)
        self._deadline_s = deadline_s
        self._client = httpx.AsyncClient(
            base_url=base_url,
            timeout=timeout_s,
            transport=transport,
            headers=UPSTREAM_HEADERS,
        )

    async def request(
        self,
        method: str,
        path: str,
        authorization: str,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        client_ip: str | None = None,
    ) -> str:
        """Perform one API call; model-readable text on success, SporfieApiError otherwise.

        ``client_ip`` is the caller's public address as derived from a trusted proxy
        (client_ip.py). It is sent as the only X-Forwarded-For entry so the API attributes
        traffic to the real caller instead of to this server. Caller-supplied forwarding headers
        are never relayed.
        """
        headers = {"Authorization": authorization}
        if client_ip:
            headers["X-Forwarded-For"] = client_ip
        request = self._client.build_request(
            method,
            path,
            params={k: v for k, v in (params or {}).items() if v is not None},
            json=json_body,
            headers=headers,
        )
        ensure_request_target(self._client, request, path)
        status, text, truncated = await send_capped(
            self._client, request, self._gate, self._max_response_bytes, self._deadline_s
        )
        if not 200 <= status < 300:
            raise SporfieApiHttpError(status, render_error_body(text, status), error_code(text))
        body = self._render_success(text, truncated)
        return body if body else f"HTTP {status} (no content)"

    def _render_success(self, text: str, truncated: bool) -> str:
        text = text.strip()
        if not text:
            return ""
        if not truncated:
            try:
                # Re-serialize compactly: pretty-printing whitespace is pure token waste.
                text = json.dumps(json.loads(text), ensure_ascii=False, separators=(",", ":"))
            except (ValueError, RecursionError):
                pass  # not JSON (or nested past what the parser survives): pass through as is
        if truncated or len(text) > self._max_response_chars:
            text = text[: self._max_response_chars] + _TRUNCATION_MARKER
        return text


def ensure_request_target(client: httpx.AsyncClient, request: httpx.Request, path: str) -> None:
    """Refuse to send unless httpx kept the exact path and host the caller built.

    httpx normalizes URLs (for example it resolves dot segments). Tool paths are built from
    validated segments, so any difference here means validation was bypassed: fail closed.
    """
    base = client.base_url
    expected_path = base.raw_path.rstrip(b"/") + path.encode("ascii")
    sent_path = request.url.raw_path.split(b"?", 1)[0]
    if sent_path != expected_path or request.url.netloc != base.netloc:
        logger.error("Refusing request: built %r but httpx would send %s", path, request.url)
        raise SporfieApiError("Refusing to send a request whose URL differs from the one built.")


async def send_capped(
    client: httpx.AsyncClient,
    request: httpx.Request,
    gate: UpstreamGate,
    max_bytes: int,
    deadline_s: float,
) -> tuple[int, str, bool]:
    """Send ``request`` and read at most ``max_bytes`` of the body, within ``deadline_s``.

    Returns (status, text, truncated). Never follows redirects (httpx's default). Waiting for a
    slot is bounded by the gate; once admitted, the whole exchange (connect, headers, every body
    byte) must finish inside ``deadline_s``. httpx's own timeout applies per phase, so on its own
    it lets an upstream that trickles one byte per interval hold a slot for as long as it likes.
    """
    async with gate.slot():
        try:
            async with asyncio.timeout(deadline_s):
                return await _send_and_read(client, request, max_bytes)
        except TimeoutError:
            logger.warning(
                "%s %s exceeded the %ss deadline", request.method, request.url.path, deadline_s
            )
            raise SporfieApiUnreachable("the request timed out") from None


async def _send_and_read(
    client: httpx.AsyncClient, request: httpx.Request, max_bytes: int
) -> tuple[int, str, bool]:
    try:
        response = await client.send(request, stream=True)
    except httpx.HTTPError as exc:
        logger.warning("%s %s failed: %r", request.method, request.url.path, exc)
        raise SporfieApiUnreachable(_describe_transport_error(exc)) from exc
    try:
        _refuse_encoded(request, response)
        chunks, truncated = await _read_capped(response, max_bytes)
    except httpx.HTTPError as exc:
        logger.warning("%s %s failed mid-body: %r", request.method, request.url.path, exc)
        raise SporfieApiUnreachable(_describe_transport_error(exc)) from exc
    finally:
        await response.aclose()
    text = b"".join(chunks).decode(response.encoding or "utf-8", errors="replace")
    return response.status_code, text, truncated


def _refuse_encoded(request: httpx.Request, response: httpx.Response) -> None:
    """Fail closed on a compressed response, before any of its body is read.

    The request asks for ``identity``, but that is only a request. httpx would decode whatever
    the upstream chose to send, and a decoder expands a whole network chunk at once: 32 KiB of
    gzip becomes 32 MiB before the size cap could look at it. So a compressed body is never
    decoded here, and never read at all.
    """
    codings = response.headers.get_list("content-encoding", split_commas=True)
    unexpected = [c for c in (c.strip().lower() for c in codings) if c not in ("", "identity")]
    if unexpected:
        logger.warning(
            "%s %s answered with Content-Encoding %s, which is refused",
            request.method,
            request.url.path,
            ", ".join(unexpected),
        )
        raise SporfieApiError("the upstream sent a compressed response, which this server refuses")


async def _read_capped(response: httpx.Response, max_bytes: int) -> tuple[list[bytes], bool]:
    """The first ``max_bytes`` of the raw body, and whether more was left unread.

    Iterates the transport stream rather than ``aiter_bytes()``, which decodes each chunk.
    (``aiter_raw()`` is equivalent for a network response, but raises StreamConsumed for one
    that was already read when it was built, which is how in-memory test responses arrive.)
    """
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.stream:
        room = max_bytes - size
        if len(chunk) > room:
            chunks.append(chunk[:room])
            return chunks, True
        chunks.append(chunk)
        size += len(chunk)
    return chunks, False


def _describe_transport_error(exc: httpx.HTTPError) -> str:
    if isinstance(exc, httpx.TimeoutException):
        return "the request timed out"
    if isinstance(exc, httpx.ConnectError):
        return "could not connect"
    return "the connection failed"
