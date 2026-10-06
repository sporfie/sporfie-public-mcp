"""Looking around: discovery and read-only tools, as a person exploring their account."""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest


def _place_keys(places: dict) -> list[str]:
    return [place["key"] for place in places["places"] if place.get("key")]


def test_the_sports_can_be_listed(mcp):
    result = mcp.call("list_sports")
    assert not result.is_error, result.brief()
    assert "soccer" in result.text.lower()


def test_the_places_of_a_company_can_be_listed(mcp, company):
    result = mcp.call("list_places", {"company_key": company})
    assert not result.is_error, result.brief()
    assert isinstance(result.json()["places"], list)


@pytest.mark.parametrize("state", ["current", "future", "past"])
def test_the_events_of_a_company_can_be_searched_by_state(mcp, company, state):
    result = mcp.call("search_events", {"company_key": company, "state": state, "page_size": 3})
    assert not result.is_error, result.brief()
    page = result.json()
    assert "totalCount" in page and isinstance(page.get("events", []), list)


def test_a_place_can_be_asked_what_is_live_on_it(mcp, company, settings):
    place_key = settings.place_key
    if place_key is None:
        keys = _place_keys(mcp.call("list_places", {"company_key": company}).json())
        if not keys:
            pytest.skip("the company has no place: set E2E_PLACE_KEY to ask about another one")
        place_key = keys[0]
    now = datetime.now(UTC)
    asked = [
        mcp.call("get_active_event_key", {"place_key": place_key}),
        mcp.call(
            "lookup_event_by_place_and_time",
            {
                "place_key": place_key,
                "year": now.year,
                "month": now.month,
                "day": now.day,
                "hour": now.hour,
            },
        ),
    ]
    for result in asked:
        # Nothing live is an answer ("404"), and it arrives as an error, not as a success.
        assert not result.unflagged_failure, result.brief()
        assert not result.is_error or result.http_status == 404, result.brief()


@pytest.mark.parametrize("tool", ["list_places", "search_events"])
def test_a_company_the_user_does_not_administer_is_refused(mcp, foreign_company, tool):
    arguments = {"company_key": foreign_company}
    if tool == "search_events":
        arguments |= {"state": "past", "page_size": 1}
    result = mcp.call(tool, arguments)
    assert result.is_error, (
        f"{tool} served a company's data. If the credential is entitled to E2E_FOREIGN_COMPANY_KEY "
        f"the setting is wrong: name a company it is not. Answer: {result.brief()}"
    )
    assert result.http_status in {401, 403, 404}, result.brief()


def test_the_help_center_can_be_searched_and_an_article_read(mcp):
    hits = mcp.call("search_help_center", {"query": "camera setup"})
    assert not hits.is_error, hits.brief()
    article_ids = re.findall(r"^- \[(\d+)\]", hits.text, flags=re.MULTILINE)
    assert article_ids, hits.brief()
    article = mcp.call("get_help_article", {"article_id": int(article_ids[0])})
    assert not article.is_error, article.brief()
    assert article.text.startswith("# ")
    assert "Public URL:" in article.text


def test_the_help_center_sections_can_be_browsed(mcp):
    result = mcp.call("list_help_center_sections")
    assert not result.is_error, result.brief()
    assert re.search(r"^- \[\d+\]", result.text, flags=re.MULTILINE), result.brief()
