"""An integrator's day: create an event, read it, change it, point a webhook at it, delete it.

Only the tester's own company is written to. Every event is named as a test's and is deleted at
the end, whether the tests passed or not.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

import pytest

from .mcp_client import McpClient

MONTH_MS = 30 * 24 * 3600 * 1000

UNSAFE_WEBHOOKS = {
    "localhost over http": "http://localhost:8080/hook",
    "a loopback address": "https://127.0.0.1/hook",
    "the cloud metadata address": "http://169.254.169.254/latest/meta-data/",
    "a private address": "https://10.0.0.5/hook",
    "IPv6 loopback": "https://[::1]/hook",
    "a scheme that is not http": "ftp://example.com/hook",
    "credentials in the URL": "https://user:pass@example.com/hook",
    "a name that resolves to loopback": "https://localtest.me/hook",
}


@dataclass(frozen=True)
class Event:
    external_id: str
    key: str | None
    name: str

    @property
    def target(self) -> dict[str, str]:
        return {"event_key_or_external_id": self.external_id}


def _payload(company: str, name: str) -> dict[str, Any]:
    return {
        "companyKey": company,
        "name": name,
        "description": "Created by the end-to-end tests of the public MCP server.",
        "sport": "soccer",
        # An event that is not on a place takes a location and an announced time.
        "location": {"name": "MCP e2e test venue", "geoLoc": {"lat": 46.2044, "lng": 6.1432}},
        "announcedTime": int(time.time() * 1000) + MONTH_MS,  # a month away: it never starts
        "announcedDuration": 3600 * 1000,
        "notSearchable": True,
    }


@contextmanager
def temporary_event(mcp: McpClient, company: str, label: str) -> Iterator[Event]:
    """An event that exists for the duration of the block and is deleted after it."""
    external_id = f"mcp-e2e-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"
    name = f"MCP e2e {label} {external_id} (safe to delete)"
    created = mcp.call(
        "create_event", {"external_id": external_id, "event": _payload(company, name)}
    )
    try:
        assert not created.is_error, created.brief()
        body = created.json()
        yield Event(external_id, body.get("eventKey") or body.get("key"), name)
    finally:
        mcp.call("delete_event", {"event_key_or_external_id": external_id})  # 404 if already gone


@pytest.fixture(scope="module")
def event(mcp: McpClient, writable_company: str) -> Iterator[Event]:
    with temporary_event(mcp, writable_company, "lifecycle") as created:
        yield created


def test_a_created_event_can_be_read_by_external_id_and_by_key(mcp, event):
    by_external_id = mcp.call("get_event", event.target)
    assert not by_external_id.is_error, by_external_id.brief()
    assert by_external_id.json()["name"] == event.name
    assert event.key, "create_event did not return the event's key"
    by_key = mcp.call("get_event", {"event_key_or_external_id": event.key})
    assert not by_key.is_error, by_key.brief()
    assert by_key.json()["name"] == event.name


def test_creating_twice_with_one_external_id_is_a_conflict(mcp, event, writable_company):
    again = mcp.call(
        "create_event",
        {"external_id": event.external_id, "event": _payload(writable_company, event.name)},
    )
    assert again.is_error and again.http_status == 409, again.brief()


def test_an_update_is_visible_afterwards(mcp, event):
    renamed = f"{event.name} RENAMED"
    updated = mcp.call("update_event", {**event.target, "patch": {"name": renamed}})
    assert not updated.is_error, updated.brief()
    assert mcp.call("get_event", event.target).json()["name"] == renamed


@pytest.mark.parametrize("url", UNSAFE_WEBHOOKS.values(), ids=UNSAFE_WEBHOOKS.keys())
def test_a_webhook_that_points_inside_is_refused(mcp, event, url):
    result = mcp.call("watch_event", {**event.target, "webhook_url": url})
    if not result.is_error:
        mcp.call("unwatch_event", event.target)  # never leave one registered
    assert result.is_error, f"{url} was accepted as a webhook"


def test_a_public_https_webhook_can_be_registered_replaced_and_removed(mcp, event):
    # Nothing is delivered: the event does not change while a webhook is registered.
    try:
        first = mcp.call("watch_event", {**event.target, "webhook_url": "https://example.com/e2e"})
        assert not first.is_error, first.brief()
        second = mcp.call(
            "watch_event", {**event.target, "webhook_url": "https://example.com/e2e2"}
        )
        assert not second.is_error, f"a second watch should replace the first: {second.brief()}"
    finally:
        removed = mcp.call("unwatch_event", event.target)
    assert not removed.is_error, removed.brief()


def test_closing_an_event_that_never_started_is_accepted(mcp, writable_company):
    with temporary_event(mcp, writable_company, "close") as unstarted:
        closed = mcp.call("close_event", unstarted.target)
        assert not closed.is_error, closed.brief()


def test_a_deleted_event_is_gone(mcp, event):
    deleted = mcp.call("delete_event", event.target)
    assert not deleted.is_error, deleted.brief()
    gone = mcp.call("get_event", event.target)
    assert gone.is_error and gone.http_status == 404, gone.brief()
