"""Reading the caller's ``Authorization`` header, one way for every layer.

Two layers look at the header: the OAuth middleware decides whether to challenge, and the tool
layer forwards the credential to the Sporfie API. They must agree on what the header says, or a
request could pass one check and mean something else to the other. So both read it through this
module: the scheme is matched case-insensitively (RFC 7235), the credential is forwarded in its
canonical ``Bearer <token>`` form (the Sporfie API only strips a case-sensitive "Bearer "), and
a request carrying more than one Authorization header has no usable credential, because picking
one of them would be a guess.
"""

from __future__ import annotations

import re

# "Bearer", one or more spaces, then a token with no whitespace in it (RFC 6750 token68).
_BEARER = re.compile(r"bearer +(\S+)", re.IGNORECASE)


def bearer_token(value: str) -> str | None:
    """The token of an ``Authorization: Bearer <token>`` header value, or None if it is not one."""
    match = _BEARER.fullmatch(value.strip())
    return match.group(1) if match else None
