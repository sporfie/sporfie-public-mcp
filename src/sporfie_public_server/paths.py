"""Validation for tool arguments that end up in an outbound request.

Tool arguments are untrusted input: an agent can be steered by text it read elsewhere into
passing any string. A value placed in a URL path could otherwise change which endpoint a tool
calls. So every path value must match the identifier alphabet the Sporfie API itself uses, is
percent-encoded anyway, and the finished path is checked against the tool's own template.
"""

from __future__ import annotations

import re
from functools import lru_cache
from urllib.parse import quote

# Sporfie keys (Firebase push IDs such as "-MCka7Eq-SGcom52zt1f") and API externalIDs only use
# these characters; the API refuses any other character in an externalID. No '.', '/', '?', '#'
# or '%' can appear, so a value can never be a dot segment or end the path early.
_IDENTIFIER = re.compile(r"[A-Za-z0-9_-]{1,128}")
# Help Center locale codes: "en-us", "fr", "pt-br", "es-419".
_LOCALE = re.compile(r"[a-z]{2,3}(?:-[a-z0-9]{2,8})?")


class InvalidArgument(ValueError):
    """A tool argument was rejected. The message is written for the calling agent."""


def identifier(value: object, name: str) -> str:
    """A Sporfie key or externalID, unchanged, or InvalidArgument."""
    if isinstance(value, str) and _IDENTIFIER.fullmatch(value):
        return value
    raise InvalidArgument(
        f"Invalid {name}: pass the key or externalID exactly as Sporfie returned it "
        "(letters, digits, '-' and '_' only, 1 to 128 characters)."
    )


def locale(value: object) -> str:
    """A lower-cased Help Center locale code, or InvalidArgument."""
    if isinstance(value, str) and _LOCALE.fullmatch(value.lower()):
        return value.lower()
    raise InvalidArgument("Invalid locale: use a Help Center locale code such as 'en-us' or 'fr'.")


def bounded_int(value: object, name: str, minimum: int, maximum: int) -> int:
    """An int within [minimum, maximum], or InvalidArgument."""
    if isinstance(value, int) and not isinstance(value, bool) and minimum <= value <= maximum:
        return value
    raise InvalidArgument(f"Invalid {name}: use a whole number from {minimum} to {maximum}.")


def build_path(template: str, **values: object) -> str:
    """Fill each ``{}`` of ``template``, in order, with a validated and percent-encoded value.

    Keyword names are only used in error messages. The finished path must still match the
    template (same literal text, one non-empty segment per slot, no dot segment); anything else
    is a programming error and raises ValueError instead of building a request.
    """
    segments = [quote(identifier(value, name), safe="") for name, value in values.items()]
    if template.count("{}") != len(segments):
        raise ValueError(f"{template!r} needs {template.count('{}')} values, got {len(segments)}")
    path = template.format(*segments)
    if not matches_template(path, template):
        raise ValueError(f"refusing to build {path!r}: it does not match {template!r}")
    return path


def matches_template(path: str, template: str) -> bool:
    """True when ``path`` has exactly the shape of ``template`` (slots are single segments)."""
    if not _template_pattern(template).fullmatch(path):
        return False
    return all(segment not in (".", "..") for segment in path.split("/"))


@lru_cache(maxsize=64)
def _template_pattern(template: str) -> re.Pattern[str]:
    return re.compile("[^/?#]+".join(re.escape(part) for part in template.split("{}")))
