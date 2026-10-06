"""Sign in once, the way Cursor does, and keep the grant for the test runs.

    E2E_MCP_URL=https://<host>/mcp uv run python -m e2e.login

Opens the consent screen in your browser: approve it. The grant lasts weeks and the tests refresh
it as they go, so this is rarely needed. Run it again to replace the grant.
"""

from __future__ import annotations

import os
import sys

import httpx

from . import oauth, settings


def main() -> int:
    config = settings.load()
    if config is None:
        print(
            "Set E2E_MCP_URL to the MCP endpoint, for example https://<host>/mcp", file=sys.stderr
        )
        return 2
    with httpx.Client(timeout=30) as http:
        try:
            discovery = oauth.discover(config.mcp_url, http)
            store = oauth.TokenStore(config.token_file)
            wait_s = float(os.environ.get("E2E_SIGN_IN_TIMEOUT_S") or 600)
            grant = oauth.sign_in(
                http,
                discovery,
                store,
                port=config.redirect_port,
                timeout_s=wait_s,
                announce=lambda text: print(text, flush=True),
            )
        except oauth.OAuthFlowError as failure:
            print(f"sign-in failed: {failure}", file=sys.stderr)
            return 1
    print("signed in:", oauth.summary(grant))
    print(f"grant kept in {config.token_file} (readable by you only)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
