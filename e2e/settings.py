"""What the suite is pointed at, read from the environment.

Nothing environment-specific is written down here: the suite runs against whichever server
``E2E_MCP_URL`` names, with whichever company ``E2E_COMPANY_KEY`` names.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

# Hosts on which the suite refuses to create and delete events unless told it may.
PRODUCTION_HOSTS = frozenset({"mcp.sporfie.com"})


def _flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _text(name: str) -> str | None:
    return os.environ.get(name, "").strip() or None


def strict() -> bool:
    """True when a missing prerequisite must fail the run instead of skipping the test."""
    return _flag("E2E_STRICT")


@dataclass(frozen=True)
class Settings:
    mcp_url: str  # the MCP endpoint, for example https://<host>/mcp
    expected_resource: str  # the resource the server says it is (its public URL plus /mcp)
    company_key: str | None  # a company the tester administers: the only one written to
    foreign_company_key: str | None  # a company the tester does NOT administer (isolation checks)
    place_key: str | None  # a place the credential may read, for the place lookups
    access_token: str | None  # a ready-made bearer (personal API token), instead of OAuth
    token_file: Path  # where `python -m e2e.login` keeps the OAuth grant (0600)
    min_interval_s: float  # pause between tool calls: the API rate-limits per token
    redirect_port: int  # loopback port of the OAuth callback
    expected_version: str | None  # None: this checkout's version; "any": do not check
    interactive: bool  # also run the tests that need a person to approve a consent screen
    allow_prod_writes: bool

    @property
    def origin(self) -> str:
        parts = urlsplit(self.mcp_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def host(self) -> str:
        return urlsplit(self.mcp_url).hostname or ""

    @property
    def expected_origin(self) -> str:
        parts = urlsplit(self.expected_resource)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def is_production(self) -> bool:
        return self.host in PRODUCTION_HOSTS


def load() -> Settings | None:
    """The settings, or None when ``E2E_MCP_URL`` is not set (nothing to test)."""
    mcp_url = _text("E2E_MCP_URL")
    if mcp_url is None:
        return None
    mcp_url = mcp_url.rstrip("/")
    parts = urlsplit(mcp_url)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError(f"E2E_MCP_URL must be an http(s) URL, got {mcp_url!r}")
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "sporfie-public-mcp"
    slug = re.sub(r"[^A-Za-z0-9.-]+", "_", parts.netloc)
    token_file = Path(_text("E2E_TOKEN_FILE") or cache / f"e2e-{slug}.json").expanduser()
    return Settings(
        mcp_url=mcp_url,
        expected_resource=(_text("E2E_EXPECTED_RESOURCE") or mcp_url).rstrip("/"),
        company_key=_text("E2E_COMPANY_KEY"),
        foreign_company_key=_text("E2E_FOREIGN_COMPANY_KEY"),
        place_key=_text("E2E_PLACE_KEY"),
        access_token=_text("E2E_ACCESS_TOKEN"),
        token_file=token_file,
        min_interval_s=float(_text("E2E_MIN_INTERVAL_S") or 1.15),
        redirect_port=int(_text("E2E_REDIRECT_PORT") or 8787),
        expected_version=_text("E2E_EXPECTED_VERSION"),
        interactive=_flag("E2E_INTERACTIVE"),
        allow_prod_writes=_flag("E2E_ALLOW_PROD_WRITES"),
    )
