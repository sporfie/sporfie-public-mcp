"""Checks over the whole run, so it goes last."""

from __future__ import annotations


def test_no_failure_was_reported_as_a_success(mcp):
    """An agent reads ``isError``. A failure that arrives as plain text would pass for an answer."""
    unflagged = [f"{r.name}: {r.brief(100)}" for r in mcp.results if r.unflagged_failure]
    assert not unflagged, unflagged
