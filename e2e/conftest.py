"""Fixtures shared by the suite.

Every test depends, directly or not, on ``settings``: without E2E_MCP_URL there is no server to
test, so everything is skipped, or fails when E2E_STRICT=1 (which a release gate should set).
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import NoReturn

import httpx
import pytest

from . import oauth
from .mcp_client import McpClient
from .settings import Settings, load, strict


def unmet(reason: str) -> NoReturn:
    """A prerequisite is missing: skip, or fail when the run is strict."""
    if strict():
        pytest.fail(reason, pytrace=False)
    pytest.skip(reason)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "interactive: needs a person to approve a consent screen (E2E_INTERACTIVE=1)"
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    settings = load()
    if settings is not None and settings.interactive:
        return
    skip = pytest.mark.skip(reason="needs a person to approve a consent screen: E2E_INTERACTIVE=1")
    for item in items:
        if "interactive" in item.keywords:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def settings() -> Settings:
    loaded = load()
    if loaded is None:
        unmet("E2E_MCP_URL is not set: there is no server to test")
    return loaded


@pytest.fixture(scope="session")
def http() -> Iterator[httpx.Client]:
    with httpx.Client(timeout=30) as client:
        yield client


@pytest.fixture(scope="session")
def oauth_on(settings: Settings, http: httpx.Client) -> None:
    """Skips the test unless the server challenges unauthenticated requests (OAuth enabled)."""
    probe = http.post(settings.mcp_url, json=oauth.initialize_request(), headers=oauth.MCP_ACCEPT)
    challenged = "resource_metadata" in probe.headers.get("www-authenticate", "")
    if probe.status_code != 401 or not challenged:
        unmet("OAuth is not enabled on this server")


@pytest.fixture(scope="session")
def discovery(settings: Settings, http: httpx.Client, oauth_on: None) -> oauth.Discovery:
    return oauth.discover(settings.mcp_url, http)


@pytest.fixture(scope="session")
def access_token(settings: Settings, http: httpx.Client) -> str:
    """A credential the tests may use: a ready-made token, or the OAuth grant of e2e.login."""
    if settings.access_token:
        return settings.access_token
    store = oauth.TokenStore(settings.token_file)
    if store.grant() is None:
        unmet("no credentials: run `python -m e2e.login` (OAuth), or set E2E_ACCESS_TOKEN")
    try:
        token = store.access_token(http, oauth.discover(settings.mcp_url, http))
    except oauth.OAuthFlowError as failure:
        pytest.fail(str(failure), pytrace=False)
    assert token, "the grant disappeared from the token file"
    return token


def _root_cause(failure: BaseException) -> BaseException:
    """The first real error inside the exception groups the async transport wraps it in."""
    while isinstance(failure, BaseExceptionGroup) and failure.exceptions:
        failure = failure.exceptions[0]
    return failure


@pytest.fixture(scope="session")
def mcp(settings: Settings, access_token: str) -> Iterator[McpClient]:
    try:
        client = McpClient(settings.mcp_url, access_token, settings.min_interval_s).start()
    except Exception as failure:  # noqa: BLE001 - whatever went wrong is the test run's answer
        pytest.fail(
            f"could not open an MCP session on {settings.mcp_url}: {_root_cause(failure)!r}",
            pytrace=False,
        )
    try:
        # A rejected credential closes the session on the first call, and every later test would
        # fail with a transport error. Say so once, here, with the way out.
        first = client.call("list_sports")
        if first.is_error:
            pytest.fail(
                f"the server did not accept the credential ({first.brief(200)}). "
                "Sign in again with `python -m e2e.login`, or check E2E_ACCESS_TOKEN.",
                pytrace=False,
            )
        yield client
    finally:
        client.stop()


@pytest.fixture(scope="session")
def company(settings: Settings) -> str:
    """The company the tests read, and write to: one the tester administers."""
    if not settings.company_key:
        unmet("E2E_COMPANY_KEY is not set: the key of a company you administer on this server")
    return settings.company_key


@pytest.fixture(scope="session")
def writable_company(settings: Settings, company: str) -> str:
    if settings.is_production and not settings.allow_prod_writes:
        unmet("this is the production server: E2E_ALLOW_PROD_WRITES=1 lets the suite create events")
    return company


@pytest.fixture(scope="session")
def foreign_company(settings: Settings) -> str:
    if not settings.foreign_company_key:
        unmet("E2E_FOREIGN_COMPANY_KEY is not set: the key of a company you do NOT administer")
    return settings.foreign_company_key
