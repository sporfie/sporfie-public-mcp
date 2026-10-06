"""Upstream limits: compressed bodies are refused undecoded, admission is bounded, calls have a
total deadline.

They pin down three findings about the response-size cap. httpx decodes a whole network chunk
before the byte cap can look at it (a 31 KiB gzip body expands to 32 MiB), an
``asyncio.Semaphore`` lets waiters pile up without limit, and httpx's timeout applies per phase,
so an upstream that trickles bytes can hold a slot for as long as it likes.
"""

from __future__ import annotations

import asyncio
import gzip
import logging
import re
import time
import tracemalloc
from collections.abc import Callable
from types import SimpleNamespace

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from starlette.datastructures import Headers

import sporfie_public_server.server as srv
from sporfie_public_server.client import (
    SporfieApiError,
    SporfieApiHttpError,
    SporfieApiOverloaded,
    SporfieApiUnreachable,
)
from sporfie_public_server.config import load_config
from sporfie_public_server.oauth import TOKEN_REJECTED

from .test_hardening import AUTHED, api_client, hc_client
from .test_server import BEARER, ctx_with

# 32 MiB of 'A' compresses to about 31 KiB: the classic 1000:1 "zip bomb".
BOMB = gzip.compress(b"A" * (32 * 1024 * 1024))
EMPTY_RESULTS = b'{"results": []}'  # a valid answer for both the API and the Help Center search


class Body(httpx.AsyncByteStream):
    """A response body that is only read when the client asks for it.

    ``httpx.Response(content=...)`` is read, and decoded when it has a Content-Encoding, while
    the response is being built. That would hide exactly what these tests are about.
    """

    def __init__(self, data: bytes, chunk_size: int = 64 * 1024) -> None:
        self._data = data
        self._chunk_size = chunk_size
        self.pulled = 0
        self.closed = False

    async def __aiter__(self):
        for start in range(0, len(self._data), self._chunk_size):
            self.pulled += 1
            yield self._data[start : start + self._chunk_size]

    async def aclose(self) -> None:
        self.closed = True


def lazy(body: Body, **headers: str) -> httpx.Response:
    return httpx.Response(200, headers=headers, stream=body)


class Caller:
    """One upstream client plus a way to make the same call again (the gate is per client)."""

    def __init__(self, client, invoke: Callable[[], object]) -> None:
        self.client = client
        self._invoke = invoke

    def __call__(self):
        return self._invoke()

    @property
    def waiting(self) -> int:
        return self.client._gate.waiting


def api_caller(handler, **kwargs) -> Caller:
    client = api_client(handler, **kwargs)
    return Caller(client, lambda: client.request("GET", "/public/x", BEARER))


def hc_caller(handler, **kwargs) -> Caller:
    client = hc_client(handler, **kwargs)
    return Caller(client, lambda: client.search("camera", "en-us", 1))


@pytest.fixture(params=["api", "help-center"])
def make(request):
    """Builds a Caller for each of the two upstream clients, which share the same rails."""
    return {"api": api_caller, "help-center": hc_caller}[request.param]


class Blocker:
    """A handler whose calls all park until ``release`` is set, so a test can hold slots open."""

    def __init__(self) -> None:
        self.entered = 0
        self.release = asyncio.Event()

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        self.entered += 1
        await self.release.wait()
        return httpx.Response(200, content=EMPTY_RESULTS)


async def refused_within(
    exc_type: type[Exception], call: Callable[[], object], match: str, within_s: float = 3.0
) -> float:
    """Await ``call()``, which must raise ``exc_type``; returns how long that took.

    The outer guard turns a missing limit (a call that would wait forever) into a failure.
    """
    started = time.monotonic()
    with pytest.raises(exc_type, match=match):
        async with asyncio.timeout(within_s):
            await call()
    return time.monotonic() - started


async def until(condition: Callable[[], bool], timeout_s: float = 2.0) -> None:
    """Let other tasks run until ``condition()`` holds: a bounded poll, never a blind sleep."""
    deadline = time.monotonic() + timeout_s
    while not condition():
        assert time.monotonic() < deadline, "condition was never met"
        await asyncio.sleep(0.005)


# ----- compressed responses are refused, never decoded -----


async def test_gzip_bomb_is_refused_before_it_is_decoded(make):
    def handler(_: httpx.Request) -> httpx.Response:
        return lazy(Body(BOMB), **{"content-encoding": "gzip"})

    call = make(handler, max_response_bytes=1024)
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()  # the fixture is already built; measure only the call
        with pytest.raises(SporfieApiError, match="compressed"):
            await call()
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024  # decoding it would have taken about 32 MiB


@pytest.mark.parametrize(
    "coding",
    ["gzip", "GZIP", "deflate", "br", "zstd", "gzip, identity", "identity, gzip", "x-unknown"],
)
async def test_any_content_encoding_but_identity_is_refused_unread(make, coding):
    body = Body(b"never read")

    def handler(_: httpx.Request) -> httpx.Response:
        return lazy(body, **{"content-encoding": coding})

    call = make(handler, max_concurrency=1)
    for _ in range(2):  # twice: a refused response must give its slot back
        with pytest.raises(SporfieApiError, match="compressed"):
            await call()
    assert body.pulled == 0 and body.closed


@pytest.mark.parametrize("coding", ["identity", "Identity"])
async def test_an_identity_encoded_response_is_read_normally(make, coding):
    def handler(_: httpx.Request) -> httpx.Response:
        return lazy(Body(EMPTY_RESULTS), **{"content-encoding": coding})

    out = await make(handler)()
    assert out in ('{"results":[]}', "No Help Center articles match 'camera'.")


async def test_an_identity_response_is_still_cut_at_the_byte_cap():
    payload = b'{"blob":"' + b"x" * 10_000 + b'"}'
    body = Body(payload, chunk_size=512)

    def handler(_: httpx.Request) -> httpx.Response:
        return lazy(body, **{"content-encoding": "identity"})

    out = await api_client(handler, max_response_bytes=2048).request("GET", "/public/x", BEARER)
    assert out.startswith(payload[:2048].decode()) and "truncated" in out
    assert len(out) < 2048 + 200
    assert body.pulled <= 2048 // 512 + 1  # stopped right after the cap, never drained the rest
    assert body.closed


async def test_both_clients_ask_for_identity_encoding(make):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers["accept-encoding"])
        return httpx.Response(200, content=EMPTY_RESULTS)

    await make(handler)()
    assert seen == ["identity"]


async def test_a_success_body_nested_past_the_parser_limit_is_passed_through_as_text():
    bomb = ("[" * 1_000_000 + "]" * 1_000_000).encode()  # 2 MB, inside the byte cap

    def handler(_: httpx.Request) -> httpx.Response:
        return lazy(Body(bomb))

    out = await api_client(handler).request("GET", "/public/x", BEARER)
    assert out.startswith("[[[[") and "truncated" in out and len(out) < 20_500


# ----- admission is bounded -----


async def test_waiters_are_capped_and_the_excess_fails_fast(make, caplog):
    blocker = Blocker()
    call = make(blocker, max_concurrency=1, max_queued=2, queue_timeout_s=30)
    holder = asyncio.create_task(call())
    await until(lambda: blocker.entered == 1)  # the holder owns the only slot
    queued = [asyncio.create_task(call()) for _ in range(2)]
    await until(lambda: call.waiting == 2)  # and two calls wait for it

    # The queue is full: this one is shed at once, and the operator can see that it was.
    with caplog.at_level(logging.WARNING, logger="sporfie_public_server.client"):
        assert await refused_within(SporfieApiOverloaded, call, "busy; retry shortly") < 1
    assert re.search(
        r"(Sporfie API|Help Center) is saturated \(queue full, 2 waiting\)", caplog.text
    )

    blocker.release.set()
    await asyncio.gather(holder, *queued)  # every admitted call still completes
    assert call.waiting == 0 and blocker.entered == 3  # the shed call never reached the handler
    await call()  # and no slot leaked


async def test_a_waiter_gives_up_after_the_queue_timeout(make, caplog):
    blocker = Blocker()
    call = make(blocker, max_concurrency=1, max_queued=8, queue_timeout_s=0.1)
    holder = asyncio.create_task(call())
    await until(lambda: blocker.entered == 1)

    with caplog.at_level(logging.WARNING, logger="sporfie_public_server.client"):
        elapsed = await refused_within(SporfieApiOverloaded, call, "busy; retry shortly")
    assert 0.09 <= elapsed < 1.5  # it waited out the timeout, not the holder
    assert "no slot within 0.1s" in caplog.text
    assert call.waiting == 0

    blocker.release.set()
    await holder
    await call()  # the slot the waiter never got is still accounted for


async def test_no_queue_means_a_busy_client_sheds_at_once(make):
    blocker = Blocker()
    call = make(blocker, max_concurrency=1, max_queued=0, queue_timeout_s=30)
    holder = asyncio.create_task(call())
    await until(lambda: blocker.entered == 1)
    assert await refused_within(SporfieApiOverloaded, call, "busy") < 1
    blocker.release.set()
    await holder


async def test_a_cancelled_waiter_leaves_no_trace(make):
    blocker = Blocker()
    call = make(blocker, max_concurrency=1, max_queued=1, queue_timeout_s=30)
    holder = asyncio.create_task(call())
    await until(lambda: blocker.entered == 1)
    waiter = asyncio.create_task(call())
    await until(lambda: call.waiting == 1)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert call.waiting == 0  # the queue position was given back
    blocker.release.set()
    await holder
    await call()  # and the slot still works


# ----- calls have a total deadline -----


async def test_a_call_has_a_total_deadline_and_frees_its_slot(make):
    hang = True

    async def handler(_: httpx.Request) -> httpx.Response:
        if hang:
            await asyncio.Event().wait()  # never answers
        return httpx.Response(200, content=EMPTY_RESULTS)

    call = make(handler, max_concurrency=1, deadline_s=0.2)
    assert await refused_within(SporfieApiUnreachable, call, "timed out") < 2

    hang = False
    await call()  # the only slot was released, so this is admitted


async def test_a_trickling_body_hits_the_deadline_and_is_closed(make):
    class Trickle(httpx.AsyncByteStream):
        closed = False

        async def __aiter__(self):
            while True:  # one byte per interval: each read is "fast", the whole never ends
                yield b" "
                await asyncio.sleep(0.05)

        async def aclose(self) -> None:
            self.closed = True

    body = Trickle()
    call = make(lambda _: httpx.Response(200, stream=body), max_concurrency=1, deadline_s=0.3)
    assert await refused_within(SporfieApiUnreachable, call, "timed out") < 2
    assert body.closed


def test_the_deadline_is_never_shorter_than_the_per_phase_timeout(monkeypatch):
    monkeypatch.setenv("SPORFIE_API_TIMEOUT_S", "30")
    monkeypatch.setenv("SPORFIE_API_DEADLINE_S", "5")
    assert load_config().deadline_s == 30
    monkeypatch.setenv("SPORFIE_API_DEADLINE_S", "90")
    assert load_config().deadline_s == 90


def test_limit_settings_have_defaults_and_can_be_overridden(monkeypatch):
    for name in (
        "SPORFIE_API_TIMEOUT_S",
        "SPORFIE_API_DEADLINE_S",
        "SPORFIE_MCP_QUEUE_TIMEOUT_S",
        "SPORFIE_MCP_MAX_QUEUED_UPSTREAM",
    ):
        monkeypatch.delenv(name, raising=False)
    config = load_config()
    assert (config.deadline_s, config.queue_timeout_s, config.max_queued_upstream) == (45, 5, 64)

    monkeypatch.setenv("SPORFIE_MCP_QUEUE_TIMEOUT_S", "2.5")
    monkeypatch.setenv("SPORFIE_MCP_MAX_QUEUED_UPSTREAM", "7")
    config = load_config()
    assert (config.queue_timeout_s, config.max_queued_upstream) == (2.5, 7)


# ----- the tool layer -----


def ctx_with_scope(scope: dict) -> SimpleNamespace:
    """A tool context whose request carries an ASGI scope, as the OAuth middleware sees it."""
    request = SimpleNamespace(headers=Headers(AUTHED), client=None, scope=scope)
    return SimpleNamespace(request_context=SimpleNamespace(request=request))


async def test_overload_is_a_plain_tool_error_never_a_token_rejection(monkeypatch):
    blocker = Blocker()
    monkeypatch.setattr(srv, "_CLIENT", api_client(blocker, max_concurrency=1, max_queued=0))
    holder = asyncio.create_task(srv.get_event("e1", ctx_with(AUTHED)))
    await until(lambda: blocker.entered == 1)

    scope: dict = {}
    with pytest.raises(ToolError) as err:
        async with asyncio.timeout(3):
            await srv.get_event("e2", ctx_with_scope(scope))
    assert str(err.value) == "The server is busy; retry shortly."
    assert TOKEN_REJECTED not in scope  # the API never spoke, so the token was not rejected

    blocker.release.set()
    await holder


async def test_help_center_overload_is_a_tool_error(monkeypatch):
    blocker = Blocker()
    monkeypatch.setattr(srv, "_HC", hc_client(blocker, max_concurrency=1, max_queued=0))
    holder = asyncio.create_task(srv.search_help_center("camera"))
    await until(lambda: blocker.entered == 1)
    with pytest.raises(ToolError, match="^The server is busy; retry shortly.$"):
        async with asyncio.timeout(3):
            await srv.search_help_center("camera")
    blocker.release.set()
    await holder


async def test_compressed_upstream_answer_is_a_tool_error(monkeypatch):
    def handler(_: httpx.Request) -> httpx.Response:
        return lazy(Body(BOMB), **{"content-encoding": "gzip"})

    monkeypatch.setattr(srv, "_CLIENT", api_client(handler))
    with pytest.raises(ToolError, match="compressed response"):
        await srv.list_sports(ctx_with(AUTHED))


def test_the_refusal_is_not_an_http_error():
    # An HTTP error carries an upstream status and body; a refused response has neither.
    assert not issubclass(SporfieApiOverloaded, SporfieApiHttpError)
    assert issubclass(SporfieApiOverloaded, SporfieApiError)
