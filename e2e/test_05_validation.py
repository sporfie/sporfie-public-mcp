"""Bad input: a clear refusal, never a success and never somebody else's route."""

from __future__ import annotations

import pytest

NOT_THERE = "doesnotexist12345"

NOT_A_KEY = {
    "empty": "",
    "a space": "a b",
    "a slash": "a/b",
    "a query delimiter": "a?x=1",
    "a fragment": "a#x",
    "unicode": "évènement",
    "200 characters": "x" * 200,
    "dot-dot and a real route": "../sports",
    "percent-encoded dot-dot": "%2e%2e%2fsports",
}


@pytest.mark.parametrize("value", NOT_A_KEY.values(), ids=NOT_A_KEY.keys())
def test_an_identifier_that_is_not_a_key_is_refused(mcp, value):
    result = mcp.call("get_event", {"event_key_or_external_id": value})
    assert result.is_error, result.brief()
    assert "soccer" not in result.text.lower(), "the identifier was followed to another route"


ABSENT = {
    "an event": ("get_event", {"event_key_or_external_id": NOT_THERE}),
    "a moment": ("get_moment", {"moment_key": NOT_THERE}),
    "updating a moment": (
        "update_moment",
        {"moment_key": NOT_THERE, "patch": {"metadata": {"e2e": True}}},
    ),
    "deleting a moment": ("delete_moment", {"moment_key": NOT_THERE}),
    "a webhook": ("unwatch_event", {"event_key_or_external_id": NOT_THERE}),
}

# A gap of the API itself, recorded rather than hidden: it turns red, strictly, once it is fixed.
ABSENT_GAPS = {"updating a moment": "the API answers 500, not 404, for an unknown moment"}


def _absent():
    def expected_failure(label):
        gap = ABSENT_GAPS.get(label)
        return [pytest.mark.xfail(reason=gap, strict=True)] if gap else []

    return [
        pytest.param(tool, arguments, id=label, marks=expected_failure(label))
        for label, (tool, arguments) in ABSENT.items()
    ]


@pytest.mark.parametrize("tool,arguments", _absent())
def test_something_that_does_not_exist_is_an_error_that_says_so(mcp, tool, arguments):
    result = mcp.call(tool, arguments)
    assert result.is_error, result.brief()
    assert result.http_status == 404, result.brief()


@pytest.mark.parametrize(
    "arguments,names",
    [
        ({"state": "bogus"}, "state"),
        ({"page_size": 0}, "page_size"),
        ({"page_size": 1000}, "page_size"),
        ({"page": -1}, "page"),
    ],
    ids=["unknown state", "page size 0", "page size 1000", "negative page"],
)
def test_a_search_outside_its_limits_is_refused_and_names_the_parameter(
    mcp, company, arguments, names
):
    result = mcp.call("search_events", {"company_key": company, **arguments})
    assert result.is_error, result.brief()
    assert names in result.text, result.brief()


def test_a_timestamp_that_is_not_a_number_is_refused(mcp):
    result = mcp.call(
        "register_click", {"event_key_or_external_id": NOT_THERE, "timestamp_ms": "yesterday"}
    )
    assert result.is_error, result.brief()


@pytest.mark.parametrize(
    "tool,arguments",
    [
        ("get_help_article", {"article_id": 0}),
        ("search_help_center", {"query": "camera", "page": 100000}),
        ("search_help_center", {"query": "camera", "locale": "../en"}),
    ],
    ids=["article 0", "page 100000", "locale that is a path"],
)
def test_the_help_center_tools_refuse_bad_parameters(mcp, tool, arguments):
    result = mcp.call(tool, arguments)
    assert result.is_error, result.brief()
