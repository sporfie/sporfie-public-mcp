"""Turn an upstream error body into text that is safe to show an agent.

An error answer can carry what the caller must not see: stack traces, exception and class names,
SQL and JDBC text, internal paths. Denying a few known field names does not hold, because the
next framework or endpoint names them differently or nests them. So this is an allowlist:

  * JSON (any status) is rebuilt from a fixed set of fields that describe what the caller did
    wrong, at every depth; everything else is dropped. Strings that survive are scrubbed of
    lines that look like server internals, and cut short.
  * Plain text or HTML is shown (stripped, scrubbed, short) only for a 4xx answer.
  * Anything else, meaning a 5xx or an unexpected status, or a body with nothing safe in it,
    becomes a generic message with a short reference. The raw body goes to the server log under
    that reference and never to the caller.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any

from .text import strip_html

logger = logging.getLogger(__name__)

# The whole rendered body, whatever its source: error bodies are for diagnosis, not data.
MAX_ERROR_CHARS = 2000

_MAX_STRING_CHARS = 300  # one JSON string value
_MAX_TEXT_CHARS = 500  # a plain-text or HTML body
_MAX_ITEMS = 10  # entries kept from a list
_MAX_DEPTH = 4  # nesting of dicts and lists kept
# The scrubber runs regexes on the event loop, over text an upstream (and, through echoed input,
# a caller) controls, so its work is bounded: this many characters of any one string, and this
# many in total across one body.
_SCAN_CHARS = 2000
_SCAN_BUDGET = 8000

# Fields that say what the caller did wrong, in the shapes the Sporfie API (code/message), Spring
# Boot (status/error), RFC 7807 (title/detail), OAuth (error_description), Zendesk
# (error/description) and bean validation (errors of field/defaultMessage/errorCode) use.
# Everything else is dropped, for example data, path, timestamp, trace, exception, cause, class
# names and rejected values, which are the fields that leak internals or echo input.
_SAFE_KEYS = frozenset(
    {
        "code",
        "error",
        "message",
        "error_description",
        "description",
        "status",
        "title",
        "detail",
        "field",
        "errorCode",
        "defaultMessage",
        "errors",
        "details",
    }
)

# A line matching any of these is dropped. Better to lose a line of a message than to show a
# frame, a class name or a query: the reference id in the generic message covers the diagnosis.
_INTERNAL_LINE = re.compile(
    "|".join(
        f"(?:{pattern})"
        for pattern in [
            # stack frames: "at com.x.Y.m(Y.java:1)", "at java.…", "... 12 more"
            r"^\s*at\s+[\w$<>]+(?:\.[\w$<>]+)+\s*\(",
            r"^\s*at\s+(?:com|org|java|javax|jakarta|sun|jdk|net|io)\.",
            r"^\s*(?:Caused\s+by|Suppressed)\s*:",
            r"^\s*\.\.\.\s*\d+\s+(?:more|common\s+frames\s+omitted)",
            # file and line of a frame: "Y.java:1", "server.js:12:5", "app.py:88"
            r"(?<![\w$-])[\w$-]+\.(?:java|kt|scala|groovy|py|js|ts|mjs):\d+",
            r"Traceback\s+\(most\s+recent\s+call\s+last\)",
            r'^\s*File\s+"[^"]+",\s+line\s+\d+',
            r"\bnode_modules/",
            # fully-qualified class names, and an exception rendered as "Name: message"
            r"(?<![\w./:@-])(?:[a-z_]\w*\.){2,}[A-Z][\w$]*(?:Exception|Error|Throwable)\b",
            r"\b[A-Z][\w$]*(?:Exception|Error)\s*:",
            r"(?<![\w./:@-])(?:com|org|net|io|java|javax|jakarta|sun|jdk)\.[a-z]\w*\.\w",
            # database internals
            r"\bSQLException\b|\bSQLState\b|\bSQL\s*\[|\bPSQLException\b",
            r"\borg\.(?:hibernate|springframework|postgresql|apache)\b|\bjdbc:",
            r"(?i:could\s+not\s+execute\s+(?:statement|query))",
            r"(?i:violates\s.{0,80}\sconstraint|\bconstraint\s*\[)",
            r'(?i:\b(?:relation|column)\s+"[^"]{1,80}"\s+.{0,40}(?:does\s+not\s+exist|of\s+relation))',
            # a SQL statement: a verb, its clause keyword, then a bind marker, WHERE or VALUES
            (
                r"(?i:\b(?:select|insert|update|delete)\b.{0,100}?(?:\bfrom\b|\binto\b|\bset\b)"
                r".{0,100}?(?:\?|\bwhere\b|\bvalues\s*\(|\w_\d\.))"
            ),
        ]
    )
)

_NOTHING = object()  # marks "no safe content", which None cannot: JSON null is a value


def render_error_body(text: str, status: int, source: str = "The Sporfie API") -> str:
    """A short, display-safe version of an error body.

    ``source`` names the upstream in the generic message. An empty body stays empty, since
    there is nothing to hide and nothing to log.
    """
    text = text.strip()
    if not text:
        return ""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        shown = _plain_text(text) if 400 <= status < 500 else ""
    else:
        safe = _Reducer().reduce(data)
        shown = "" if safe is _NOTHING else _dump(safe)
    if not shown:
        return _generic(text, status, source)
    if len(shown) > MAX_ERROR_CHARS:
        shown = shown[:MAX_ERROR_CHARS] + " … [truncated]"
    return shown


def error_code(text: str) -> str | None:
    """The ``code`` (or ``error``) string of a JSON error body, if there is one.

    Read from the raw body: it classifies the answer (see ``_TOKEN_REJECTED_CODES``) and is
    never shown, so it is not subject to the display allowlist.
    """
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    code = data.get("code", data.get("error"))
    return code if isinstance(code, str) else None


class _Reducer:
    """One pass of the allowlist over one body, within a total scan budget."""

    def __init__(self) -> None:
        self._budget = _SCAN_BUDGET

    def reduce(self, value: Any, depth: int = 0) -> Any:
        """``value`` reduced to what may be shown, or ``_NOTHING`` when none of it may."""
        if isinstance(value, str):
            text = self._scrub(value)
            return _cut(text, _MAX_STRING_CHARS) if text else _NOTHING
        if isinstance(value, bool | int | float):
            return value
        if depth >= _MAX_DEPTH:
            return _NOTHING
        if isinstance(value, dict):
            kept = {}
            for key, item in value.items():
                if key in _SAFE_KEYS and (safe := self.reduce(item, depth + 1)) is not _NOTHING:
                    kept[key] = safe
            return kept or _NOTHING
        if isinstance(value, list):
            items = (self.reduce(item, depth + 1) for item in value[:_MAX_ITEMS])
            return [item for item in items if item is not _NOTHING] or _NOTHING
        return _NOTHING  # null, and anything a JSON parser cannot produce

    def _scrub(self, text: str) -> str:
        if self._budget <= 0:
            return ""  # out of budget: show nothing rather than read on
        self._budget -= min(len(text), _SCAN_CHARS)
        return _scrub(text)


def _plain_text(text: str) -> str:
    if "<" in text and ">" in text:
        text = strip_html(text)
    return _cut(_scrub(text), _MAX_TEXT_CHARS)


def _scrub(text: str) -> str:
    """``text`` without the lines that look like server internals, joined onto one line."""
    lines = (line.strip() for line in text[:_SCAN_CHARS].splitlines())
    return " ".join(line for line in lines if line and not _INTERNAL_LINE.search(line))


def _cut(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit].rstrip() + " …"


def _dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _generic(raw: str, status: int, source: str) -> str:
    """The message shown when nothing in ``raw`` may be, with a reference to find it in the log."""
    reference = uuid.uuid4().hex[:8]
    # The body itself is never logged. Redacting it can miss a credential an upstream echoed back
    # (a Basic header, a password with spaces), and a log line outlives the request: the reference,
    # the status and the size are what the backend's own log needs to find the request.
    logger.warning(
        "%s error body withheld (ref %s, HTTP %s, %d characters)",
        source,
        reference,
        status,
        len(raw),
    )
    return f"{source} could not process the request (HTTP {status}). Reference: {reference}."
