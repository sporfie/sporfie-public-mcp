"""The Cursor plugin package is valid, points at real files, and agrees with the server.

Cursor reviews a plugin by hand and validates its manifest against a strict schema
(``additionalProperties: false``), so a stray key or a dangling path is a rejected submission.
These tests keep the manifest, ``mcp.json``, the logo, the agent rule and the README links
consistent with each other and with the package.
"""

from __future__ import annotations

import base64
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

import pytest

import sporfie_public_server
import sporfie_public_server.server as srv
from sporfie_public_server.client import USER_AGENT

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / ".cursor-plugin" / "plugin.json"
SERVER_URL = "https://mcp.sporfie.com/mcp"

# The keys Cursor's plugin.schema.json allows at the top level.
ALLOWED_KEYS = {
    "name",
    "displayName",
    "description",
    "version",
    "minClientVersions",
    "author",
    "publisher",
    "homepage",
    "repository",
    "license",
    "logo",
    "keywords",
    "category",
    "tags",
    "commands",
    "agents",
    "skills",
    "rules",
    "hooks",
    "variables",
    "mcpServers",
}
NAME = re.compile(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?")
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z.-]+)?")
MAX_LOGO_BYTES = 200 * 1024


def manifest() -> dict:
    return json.loads(MANIFEST.read_text())


def package_version() -> str:
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]


def repo_path(relative: str) -> Path:
    """A path from the manifest, which must be relative and stay inside the repository."""
    assert not Path(relative).is_absolute() and ".." not in Path(relative).parts, relative
    resolved = (ROOT / relative).resolve()
    assert resolved.is_relative_to(ROOT), relative
    return resolved


# ----- the manifest -----


def test_manifest_only_uses_keys_cursors_schema_allows():
    data = manifest()
    assert set(data) <= ALLOWED_KEYS, set(data) - ALLOWED_KEYS
    assert set(data["author"]) <= {"name", "email"} and data["author"]["name"]


def test_name_is_kebab_case_and_the_listing_fields_are_present():
    data = manifest()
    assert data["name"] == "sporfie" and NAME.fullmatch(data["name"])
    for field in ("description", "version", "license", "homepage", "repository", "logo"):
        assert data[field], field
    assert data["license"] == "Apache-2.0"
    assert data["repository"] == "https://github.com/sporfie/sporfie-public-mcp"
    assert data["homepage"].startswith("https://") and data["repository"].startswith("https://")
    assert data["keywords"] and all(isinstance(k, str) for k in data["keywords"])


def test_version_is_the_package_version_everywhere():
    version = package_version()
    assert SEMVER.fullmatch(version)
    assert manifest()["version"] == version
    assert sporfie_public_server.__version__ == version  # re-run `uv sync` if this one differs
    assert USER_AGENT == f"sporfie-public-mcp/{version}"


def test_every_path_in_the_manifest_is_relative_and_exists():
    data = manifest()
    assert repo_path(data["logo"]).is_file()
    assert repo_path(data["mcpServers"]).is_file()
    assert any(repo_path(data["rules"]).glob("*.mdc"))


def test_the_license_file_is_apache_2():
    assert "Apache License" in (ROOT / "LICENSE").read_text()[:200]


# ----- mcp.json -----


def test_mcp_json_points_at_the_hosted_server_and_holds_no_credentials():
    config = json.loads(repo_path(manifest()["mcpServers"]).read_text())
    assert set(config) == {"mcpServers"} and set(config["mcpServers"]) == {"sporfie"}
    server = config["mcpServers"]["sporfie"]
    assert server == {"type": "http", "url": SERVER_URL}  # no headers, env or auth: OAuth signs in


# ----- the logo -----


def test_the_logo_is_a_small_static_svg():
    logo = repo_path(manifest()["logo"])
    assert logo.suffix == ".svg" and logo.stat().st_size < MAX_LOGO_BYTES
    text = logo.read_text()
    assert ET.fromstring(text).tag == "{http://www.w3.org/2000/svg}svg"
    for active in ("<script", "onload", "onclick", "foreignobject", "href=", "<image", "data:"):
        assert active not in text.lower(), active


# ----- the agent rule -----


def rule() -> tuple[dict[str, str], str]:
    """The rule's frontmatter as plain key/value text, and its body."""
    path = next(repo_path(manifest()["rules"]).glob("*.mdc"))
    _, frontmatter, body = path.read_text().split("---\n", 2)
    fields = dict(line.split(":", 1) for line in frontmatter.strip().splitlines())
    return {key.strip(): value.strip() for key, value in fields.items()}, body


def test_the_rule_is_agent_requested_with_a_description():
    fields, _ = rule()
    assert set(fields) == {"description", "globs", "alwaysApply"}
    assert fields["alwaysApply"] == "false" and fields["globs"] == ""  # applied on its description
    assert len(fields["description"]) > 40


def test_the_rule_is_short_and_covers_the_safety_points():
    _, body = rule()
    bullets = [line for line in body.splitlines() if line.startswith("- ")]
    assert 6 <= len(bullets) <= 10
    for point in ("close_event", "permanent", "milliseconds", "search_events", "Confirm"):
        assert point in body, point
    assert re.search(r"never[^.]*\btoken", body, re.IGNORECASE)  # the agent never handles tokens


async def test_every_tool_the_rule_names_exists():
    _, body = rule()
    verbs = "get|list|search|create|update|close|delete|register|watch|unwatch|lookup"
    named = set(re.findall(rf"`((?:{verbs})_[a-z_]+)`", body))
    tools = {t.name for t in await srv.mcp.list_tools()}
    assert named and named <= tools, named - tools


# ----- the README's install links -----


def install_links() -> list[tuple[str, dict]]:
    """(link, decoded config) for each MCP install link in the README."""
    readme = (ROOT / "README.md").read_text()
    links = re.findall(
        r"(?:https://cursor\.com/install-mcp|cursor://[\w.-]+/mcp/install)\?[^\s)`]+", readme
    )
    decoded = []
    for link in links:
        query = parse_qs(urlparse(link).query)
        assert query["name"] == ["sporfie"], link
        decoded.append((link, json.loads(base64.b64decode(unquote(query["config"][0])))))
    return decoded


def test_the_readme_install_links_configure_the_same_server_as_mcp_json():
    links = install_links()
    assert len(links) == 2  # the https link and the cursor:// deeplink
    for link, config in links:
        assert config == {"url": SERVER_URL}, link  # and no credentials


def test_the_readme_manual_config_is_the_same_server():
    readme = (ROOT / "README.md").read_text()
    assert f'"sporfie": {{ "url": "{SERVER_URL}" }}' in readme


# ----- the container image -----


def test_the_image_copies_only_what_the_server_needs():
    dockerfile = (ROOT / "Dockerfile").read_text()
    copied = {
        source
        for line in dockerfile.splitlines()
        if line.startswith("COPY ") and "--from" not in line
        for source in line.split()[1:-1]
    }
    assert copied == {"pyproject.toml", "uv.lock", "src/"}  # plugin files never enter the image
    # uvicorn's limit counts idle keep-alive connections and 503s the health check, which would
    # take a busy pod out of rotation: memory is bounded by the request cap instead.
    assert "UVICORN_LIMIT_CONCURRENCY" not in dockerfile
    assert "UVICORN_LIMIT_CONCURRENCY" not in (ROOT / "README.md").read_text()


@pytest.mark.parametrize("stray", ["server.json", "HANDOFF.md"])
def test_no_registry_or_handoff_files_are_shipped(stray):
    assert not (ROOT / stray).exists()
