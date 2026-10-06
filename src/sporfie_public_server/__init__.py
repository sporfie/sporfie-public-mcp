"""Sporfie Public API MCP server — see server.py for the full story."""

from importlib.metadata import PackageNotFoundError, version

try:
    # The one place the version is read: the installed package's own metadata (pyproject.toml).
    __version__ = version("sporfie-public-server")
except PackageNotFoundError:  # a source tree that was never installed
    __version__ = "0.0.0+unknown"
