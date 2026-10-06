"""Error bodies reach an agent only as an allowlist of safe fields.

The old sanitizer dropped five top-level keys, so nested ``exception`` fields, SQL and class
names inside messages, and plaintext Java traces all passed through. These tests pin down the
allowlist that replaced it.
"""

from __future__ import annotations

import json
import logging
import re
import time

import httpx
import pytest

from sporfie_public_server.client import SporfieApiHttpError
from sporfie_public_server.error_body import MAX_ERROR_CHARS, error_code, render_error_body

from .test_hardening import api_client, hc_client
from .test_server import BEARER

LOGGER = "sporfie_public_server.error_body"
GENERIC = re.compile(
    r"The Sporfie API could not process the request \(HTTP (\d{3})\)\. Reference: ([0-9a-f]{8})\."
)
TRACE = (
    "java.lang.IllegalStateException: boom\n"
    "\tat com.sporfie.events.SecretRepo.load(SecretRepo.java:99)\n"
    "\tat java.base/java.lang.Thread.run(Thread.java:840)\n"
)


def shown(body: object, status: int = 400) -> str:
    return render_error_body(json.dumps(body), status)


# ----- the shapes the backend produces are kept, minus what is not safe -----


def test_error_resource_shape_keeps_code_and_message():
    body = {"code": "client_app_token_invalid", "message": "The token is invalid", "data": None}
    assert (
        shown(body, 401) == '{"code":"client_app_token_invalid","message":"The token is invalid"}'
    )


def test_spring_default_error_keeps_status_and_error_only():
    body = {
        "timestamp": "2026-09-29T10:00:00.000+00:00",
        "status": 404,
        "error": "Not Found",
        "path": "/public/events/x",
    }
    assert shown(body, 404) == '{"status":404,"error":"Not Found"}'


def test_validation_errors_keep_field_message_and_code_only():
    body = {
        "errors": [
            {
                "field": "name",
                "defaultMessage": "must not be blank",
                "errorCode": "NotBlank",
                "rejectedValue": "hunter2",
                "objectName": "eventRequest",
                "codes": ["NotBlank.eventRequest.name"],
                "arguments": [{"code": "name"}],
            }
        ]
    }
    assert json.loads(shown(body)) == {
        "errors": [
            {"field": "name", "defaultMessage": "must not be blank", "errorCode": "NotBlank"}
        ]
    }


def test_zendesk_error_keeps_error_and_description():
    body = {"error": "RecordNotFound", "description": "Not found"}
    assert json.loads(shown(body, 404)) == body


def test_nested_exception_and_trace_fields_are_dropped():
    body = {
        "error": "Bad Request",
        "errors": [
            {
                "message": "name is required",
                "exception": "com.sporfie.events.InvalidEventException",
                "trace": "at com.sporfie.X(X.java:1)",
                "cause": {"message": "inner secret"},
            }
        ],
        "details": {"exception": "java.lang.IllegalStateException", "message": "check the dates"},
    }
    out = shown(body)
    assert json.loads(out) == {
        "error": "Bad Request",
        "errors": [{"message": "name is required"}],
        "details": {"message": "check the dates"},
    }
    for leaked in ("com.sporfie", "trace", "inner secret", "IllegalState", "exception"):
        assert leaked not in out


# ----- strings are scrubbed of internals -----


@pytest.mark.parametrize(
    "message",
    [
        "could not execute statement; SQL [insert into events (name) values (?)]; constraint [uk]",
        "com.sporfie.events.EventNotFoundException: no event abc",
        "org.hibernate.exception.ConstraintViolationException: could not execute statement",
        'ERROR: duplicate key value violates unique constraint "uk_events_external_id"',
        "select e1_0.key from event e1_0 where e1_0.key=?",
        "update event set name=? where key=?",
        "jdbc:postgresql://db.example.test:5432/appdb",
        "java.lang.IllegalStateException: boom",
        'NullPointerException: Cannot invoke "com.sporfie.Foo.bar()" because "x" is null',
        "at com.sporfie.events.EventService.find(EventService.java:42)",
        'File "/srv/app/handler.py", line 12, in handle',
    ],
)
def test_internals_in_a_message_are_withheld(message):
    assert json.loads(shown({"code": "bad_request", "message": message})) == {"code": "bad_request"}


def test_only_the_lines_that_look_like_internals_are_blanked():
    message = (
        "Event not found\n"
        "\tat com.sporfie.events.EventService.find(EventService.java:42)\n"
        "Caused by: java.sql.SQLException: ORA-1"
    )
    assert json.loads(shown({"message": message})) == {"message": "Event not found"}


@pytest.mark.parametrize(
    "message",
    [
        "Event not found",
        "must not be blank",
        "Invalid Authorization header",
        "Invalid externalID: letters, digits, '-' and '_' only",
        "Contact support@sporfie.com for help",
        "See https://www.sporfie.com/settings/developer",
        "Select a sport from the list",
        "Cannot delete from a closed event",
        "startTime must be before endTime (epoch ms)",
    ],
)
def test_ordinary_messages_survive_the_scrubber(message):
    assert json.loads(shown({"message": message})) == {"message": message}


# ----- what is shown stays small -----


def test_long_strings_and_lists_are_cut():
    body = {"message": "x" * 1000, "errors": [{"message": str(i)} for i in range(50)]}
    out = json.loads(shown(body))
    assert len(out["message"]) <= 302 and out["message"].endswith(" …")
    assert len(out["errors"]) == 10


def test_the_whole_rendered_body_is_capped():
    body = {"errors": [{"message": "m" * 290 + str(i)} for i in range(10)]}
    out = shown(body)
    assert len(out) <= MAX_ERROR_CHARS + len(" … [truncated]") and out.endswith("[truncated]")


def test_nesting_beyond_the_depth_limit_is_dropped():
    deep = {"details": {"details": {"details": {"details": {"message": "too deep"}}}}}
    assert "too deep" not in shown(deep)


@pytest.mark.parametrize("status", [400, 500])
def test_absurdly_nested_json_does_not_crash_the_renderer(status):
    # 2 MB, inside the response cap. json.loads raises RecursionError here, which is not a
    # ValueError (on older interpreters it does so at a far smaller depth).
    bomb = "[" * 1_000_000 + "]" * 1_000_000
    assert isinstance(render_error_body(bomb, status), str)
    assert error_code(bomb) is None


def test_the_scan_budget_bounds_how_much_of_one_body_is_read():
    body = {"errors": [{"message": "ok " + "word " * 400} for _ in range(10)]}  # ~2000 chars each
    kept = json.loads(shown(body))["errors"]
    assert 1 <= len(kept) < 10  # the rest is dropped once the per-body budget is spent


def test_scrubbing_a_hostile_body_takes_bounded_time():
    # Error bodies can echo input a caller chose, and the scrubber runs on the event loop.
    hostile = "select from update set insert into " * 400
    body = {key: hostile for key in ("code", "message", "detail", "title", "description")}
    body["errors"] = [dict(body) for _ in range(10)]
    started = time.perf_counter()
    render_error_body(json.dumps(body), 400)
    assert time.perf_counter() - started < 1.0


# ----- text bodies -----


def test_a_4xx_html_page_is_stripped_to_short_text():
    page = "<html><body><h1>Forbidden</h1><p>You do not have access.</p></body></html>"
    assert render_error_body(page, 403) == "Forbidden You do not have access."


def test_a_4xx_text_body_loses_its_internal_lines_and_stays_short():
    assert render_error_body("Bad request\n\tat com.sporfie.A.b(A.java:1)", 400) == "Bad request"
    assert len(render_error_body("word " * 1000, 400)) <= 502


def test_a_4xx_body_that_is_all_internals_is_withheld():
    assert GENERIC.fullmatch(render_error_body(TRACE, 400))


@pytest.mark.parametrize("status", [500, 502, 503, 302])
def test_text_bodies_outside_4xx_are_never_shown(status):
    page = "<html><body><h1>Internal Server Error</h1></body></html>"
    out = render_error_body(page, status)
    assert GENERIC.fullmatch(out) and "Internal Server Error" not in out


def test_an_empty_body_stays_empty_for_every_status(caplog):
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        for status in (400, 404, 500, 502):
            assert render_error_body("  \n", status) == ""
    assert not caplog.records  # nothing to hide, nothing to log


# ----- the generic message and the log -----


def test_a_java_trace_on_a_500_becomes_a_reference_and_the_log_names_it_without_the_body(caplog):
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        out = render_error_body(TRACE, 500)
    match = GENERIC.fullmatch(out)
    assert match and match.group(1) == "500"
    assert "SecretRepo" not in out and "IllegalState" not in out
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert match.group(2) in record.getMessage() and "SecretRepo" not in caplog.text


def test_a_body_cannot_forge_log_lines_or_grow_the_log(caplog):
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        render_error_body("line\n" * 5000, 502)
    (record,) = caplog.records
    assert "\n" not in record.getMessage() and "line" not in record.getMessage()
    assert len(record.getMessage()) < 200


def test_each_withheld_body_gets_its_own_reference():
    refs = {GENERIC.fullmatch(render_error_body(TRACE, 500)).group(2) for _ in range(5)}
    assert len(refs) == 5


def test_a_500_json_body_with_nothing_safe_is_generic():
    body = {"trace": "at com.sporfie.A(A.java:1)", "exception": "java.lang.X"}
    assert GENERIC.fullmatch(shown(body, 500))


def test_a_500_json_body_keeps_what_is_safe_without_a_reference(caplog):
    body = {"error": "Internal Server Error", "status": 500, "trace": "at com.sporfie.A(A.java:1)"}
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        out = shown(body, 500)
    assert out == '{"error":"Internal Server Error","status":500}'
    assert not caplog.records


# ----- classifying a rejected token -----


@pytest.mark.parametrize(
    "body,expected",
    [
        ('{"code":"invalid_bearer"}', "invalid_bearer"),
        ('{"error":"invalid_bearer"}', "invalid_bearer"),
        ('{"code":"Invalid Authorization header","message":"x"}', "Invalid Authorization header"),
        ('{"code":"a","error":"b"}', "a"),
        ('{"error":{"code":"x"}}', None),
        ('{"code":401}', None),
        ("not json", None),
        ("[1]", None),
        ("", None),
    ],
)
def test_error_code_reads_the_raw_body(body, expected):
    assert error_code(body) == expected


async def test_the_token_rejection_code_survives_display_sanitizing():
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, json={"code": "invalid_bearer", "message": "bad", "data": {"x": 1}}
        )

    with pytest.raises(SporfieApiHttpError) as err:
        await api_client(handler).request("GET", "/public/x", BEARER)
    assert err.value.code == "invalid_bearer"
    assert err.value.body == '{"code":"invalid_bearer","message":"bad"}'


# ----- through the clients -----


async def test_a_500_html_page_reaches_the_agent_only_as_a_reference(caplog):
    page = "<html><body><h1>Internal Server Error</h1><p>" + "detail " * 1000 + "</p></body></html>"

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(500, html=page)

    with caplog.at_level(logging.WARNING, logger=LOGGER), pytest.raises(SporfieApiHttpError) as err:
        await api_client(handler).request("GET", "/public/x", BEARER)
    assert err.value.status == 500 and GENERIC.fullmatch(err.value.body)
    assert "Internal Server Error" not in str(err.value)
    assert "Internal Server Error" not in caplog.text  # the log has the reference, not the body
    assert "test-token-123" not in caplog.text  # and the caller's credential is never logged


async def test_help_center_errors_are_sanitized_the_same_way(caplog):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/articles/404.json"):
            return httpx.Response(404, json={"error": "RecordNotFound", "description": "Nope"})
        return httpx.Response(500, text=TRACE)

    client = hc_client(handler)
    with pytest.raises(SporfieApiHttpError) as missing:
        await client.article(404, "en-us")
    assert json.loads(missing.value.body) == {"error": "RecordNotFound", "description": "Nope"}

    with (
        caplog.at_level(logging.WARNING, logger=LOGGER),
        pytest.raises(SporfieApiHttpError) as broken,
    ):
        await client.article(500, "en-us")
    assert re.fullmatch(
        r"The Help Center could not process the request \(HTTP 500\)\. Reference: [0-9a-f]{8}\.",
        broken.value.body,
    )
    assert "SecretRepo" not in broken.value.body and "SecretRepo" not in caplog.text


JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSIsImV4cCI6MX0.c2lnbmF0dXJlLXZhbHVl"


@pytest.mark.parametrize(
    "echoed, secret",
    [
        (f"bad credential {JWT} was refused", JWT),
        ("header was Authorization: Bearer abcDEF123456xyz", "abcDEF123456xyz"),
        ("header was Authorization: Basic dXNlcjpwYXNzd29yZA==", "dXNlcjpwYXNzd29yZA=="),
        ('{"Authorization":"Basic dXNlcjpwYXNzd29yZA=="}', "dXNlcjpwYXNzd29yZA=="),
        ("callback https://user:s3cretpass@hooks.example.com/in failed", "s3cretpass"),
        ("callback https://user:s3cret pass@hooks.example.com/in failed", "pass@"),
        ("rejected url https://hooks.example.com/in?token=tok123456&x=1", "tok123456"),
        ('{"message": "x", "refresh_token": "rt-9876543210"}', "rt-9876543210"),
        ("password=hunter2hunter2 was wrong", "hunter2hunter2"),
        ('{"password":"correct horse battery staple"}', "battery staple"),
        ("password=correct horse battery staple&x=1", "battery staple"),
        ("Cookie: session=abc123def456", "abc123def456"),
    ],
)
def test_a_credential_echoed_in_a_withheld_body_never_reaches_the_log(caplog, echoed, secret):
    with caplog.at_level(logging.DEBUG):
        shown = render_error_body("at java.lang.Foo(Foo.java:1) " + echoed, 500)

    assert secret not in caplog.text
    assert secret not in shown
    (record,) = caplog.records
    assert "withheld" in record.getMessage()


def test_the_log_line_of_a_withheld_body_has_what_finds_the_request_and_nothing_of_the_body(caplog):
    body = "org.postgresql.util.PSQLException: relation foo does not exist"
    with caplog.at_level(logging.WARNING, logger=LOGGER):
        shown = render_error_body(body, 500)

    (record,) = caplog.records
    reference = re.search(r"Reference: ([0-9a-f]{8})\.", shown).group(1)
    assert f"ref {reference}" in record.getMessage()
    assert "HTTP 500" in record.getMessage()
    assert f"{len(body)} characters" in record.getMessage()
    assert "relation foo" not in caplog.text
