"""What a client sees when it connects: who the server is, and which tools it offers."""

from __future__ import annotations

import asyncio

import sporfie_public_server.server as built
from sporfie_public_server import __version__

SHAPE_FIELDS = {"name", "title", "description", "inputSchema", "annotations"}


def _shape(tool) -> dict:
    shape = tool.model_dump(mode="json", exclude_none=True, include=SHAPE_FIELDS)
    # Python 3.13+ dedents docstrings when it compiles them, so the same source reads with other
    # line breaks and indentation on another interpreter. The words are what must match.
    shape["description"] = " ".join(shape.get("description", "").split())
    return shape


def test_the_server_says_who_it_is(mcp, settings):
    info = mcp.initialized.serverInfo
    assert info.name == "sporfie-public-api"
    expected = settings.expected_version or __version__
    if expected != "any":
        assert info.version == expected, "the server does not run the version of this checkout"
    assert info.websiteUrl == "https://www.sporfie.com"
    assert {icon.mimeType for icon in info.icons} == {"image/svg+xml", "image/png"}


def test_the_protocol_is_a_current_revision(mcp):
    assert mcp.initialized.protocolVersion >= "2025-06-18"


def test_the_tools_served_are_the_tools_this_checkout_builds(mcp):
    served = {tool.name: _shape(tool) for tool in mcp.list_tools()}
    local = {tool.name: _shape(tool) for tool in asyncio.run(built.mcp.list_tools())}
    assert served.keys() == local.keys()
    for name, shape in local.items():
        assert served[name] == shape, f"{name} differs from what this checkout builds"


def test_every_tool_says_whether_it_changes_anything(mcp):
    for tool in mcp.list_tools():
        hints = tool.annotations
        assert hints is not None, f"{tool.name} has no annotations"
        assert hints.readOnlyHint is not None and hints.openWorldHint is not None, tool.name
        assert tool.title or hints.title, f"{tool.name} has no title"
        if not hints.readOnlyHint:
            assert hints.destructiveHint is not None, tool.name
            assert hints.idempotentHint is not None, tool.name
