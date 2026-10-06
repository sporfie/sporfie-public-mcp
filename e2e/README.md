# End-to-end tests

These tests drive a **deployed** server the way a person's MCP client does: connect, sign in with
OAuth, list the tools, call them, create and delete an event. Run them after a rollout, and before
promoting it. They are not part of `uv run pytest`, which runs the offline unit tests in `tests/`.

## What they cover

| File | What it checks |
|---|---|
| `test_01_challenge.py` | health probe; a request with no token, or a made-up one, is challenged for OAuth; a 300 KiB body is refused |
| `test_02_oauth.py` | resource and authorization-server metadata; dynamic registration as Cursor does it, and the redirect URIs it must refuse; PKCE and resource binding; what the token endpoint refuses |
| `test_03_catalog.py` | the server reports the version of this checkout; the tools it serves are exactly the tools this checkout builds (names, schemas, annotations) |
| `test_04_read_tools.py` | sports, places, event search, place lookups, Help Center; another company's data is refused |
| `test_05_validation.py` | bad identifiers, missing objects and out-of-range parameters come back as tool errors, never as a success and never from another route |
| `test_06_events.py` | create, read by id and by key, conflict on a repeated id, update, unsafe webhook targets refused, webhook registered, replaced and removed, close, delete |
| `test_07_connection.py` | *interactive:* token binding, refresh, the old token superseded, a refresh naming another client refused, a refresh token replaced two rotations ago revoking the whole connection |
| `test_99_hygiene.py` | no failure of the run arrived as an ordinary result instead of a tool error |

Not covered: moments (highlight clicks), which need an event that is live and recording.

## Run them

1. Point them at a server, and at a company you administer **on that server**. Events are created
   in it, then deleted.

   ```bash
   export E2E_MCP_URL=https://<host>/mcp
   export E2E_COMPANY_KEY=<company key>
   ```

2. Sign in once. A browser tab opens: approve the connection. The grant is kept in a file only you
   can read, lasts weeks, and is refreshed by the tests as they go.

   ```bash
   uv run python -m e2e.login
   ```

3. Run.

   ```bash
   uv run pytest e2e -v
   ```

   Straight after a deployment this is its verification: `test_03` fails when the server runs
   another version than this checkout, or serves other tools.

To use a personal API token instead of the OAuth grant, set `E2E_ACCESS_TOKEN`. The tests that need
no credential (`test_01`, `test_02`) run either way.

The connection test needs a person to approve a consent screen, so it is opt-in:

```bash
E2E_INTERACTIVE=1 uv run pytest e2e/test_07_connection.py
```

## Settings

| Variable | Default | Meaning |
|---|---|---|
| `E2E_MCP_URL` | *(required)* | the MCP endpoint under test |
| `E2E_COMPANY_KEY` | | a company you administer there; the tests that read or write company data need it |
| `E2E_FOREIGN_COMPANY_KEY` | | a company you do **not** administer; enables the isolation check |
| `E2E_PLACE_KEY` | | a place your credential may read, for the place lookups; otherwise the first place of `E2E_COMPANY_KEY` is used |
| `E2E_ACCESS_TOKEN` | | a ready-made bearer (personal API token), used instead of the OAuth grant |
| `E2E_TOKEN_FILE` | `~/.cache/sporfie-public-mcp/e2e-<host>.json` | where `e2e.login` keeps the client and the grant (mode 0600) |
| `E2E_EXPECTED_RESOURCE` | `E2E_MCP_URL` | the resource the server advertises, when it differs from the URL you reach it on |
| `E2E_EXPECTED_VERSION` | this checkout's | `any` skips the version check |
| `E2E_MIN_INTERVAL_S` | `1.15` | pause between tool calls; the API rate-limits per token |
| `E2E_REDIRECT_PORT` | `8787` | loopback port of the OAuth callback |
| `E2E_SIGN_IN_TIMEOUT_S` | `600` | how long `e2e.login` waits for the approval |
| `E2E_STRICT` | off | `1`: a missing prerequisite fails the run instead of skipping the test. Set it in a release gate |
| `E2E_INTERACTIVE` | off | `1`: also run the tests that need a person to approve a consent screen |
| `E2E_ALLOW_PROD_WRITES` | off | `1`: allow creating and deleting events on the production host |

## Good to know

- Each run registers one OAuth client (the registration test), and each sign-in connects one app to
  your account. Revoke connections in your Sporfie account settings when you are done.
- Events are named `MCP e2e …` and carry an `mcp-e2e-…` external id. They are deleted even when a
  test fails. A run that is killed can leave one behind: delete it.
- No test prints a token. Keep the token file private, and delete it when you no longer need it.
