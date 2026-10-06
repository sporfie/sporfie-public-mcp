# sporfie-public-mcp

The public MCP (Model Context Protocol) server for the Sporfie API, served at
**https://mcp.sporfie.com/mcp** (Streamable HTTP). It lets AI agents (Claude Code, Claude
Desktop, claude.ai, Cursor, anything MCP-capable) work with Sporfie events, moments, places and
live streams, and answer support questions from the Sporfie Help Center.

To connect an agent, see [PUBLIC_DOC.md](PUBLIC_DOC.md).

## Install in Cursor

**From the marketplace.** Open **Customize** in Cursor, search for **Sporfie**, choose
**Install**, and sign in with your Sporfie account when Cursor asks. The link to the listing goes
here once the plugin is published; browse the [Cursor Marketplace](https://cursor.com/marketplace)
until then.

**One click.** [Add to Cursor](https://cursor.com/install-mcp?name=sporfie&config=eyJ1cmwiOiJodHRwczovL21jcC5zcG9yZmllLmNvbS9tY3AifQ%3D%3D)
installs the MCP server alone. The same link as a deeplink, for use inside Cursor:
`cursor://anysphere.cursor-deeplink/mcp/install?name=sporfie&config=eyJ1cmwiOiJodHRwczovL21jcC5zcG9yZmllLmNvbS9tY3AifQ==`

**By hand.** Add the server to `~/.cursor/mcp.json`, or to `.cursor/mcp.json` in a project:

```json
{
  "mcpServers": {
    "sporfie": { "url": "https://mcp.sporfie.com/mcp" }
  }
}
```

Cursor opens your browser to sign you in the first time (OAuth, so there is no token to copy).
To use a personal API token instead, add a `headers` entry that reads it from your environment,
so the token never sits in a file:

```json
"headers": { "Authorization": "Bearer ${env:SPORFIE_API_TOKEN}" }
```

The plugin also ships one agent rule, `rules/sporfie-mcp.mdc`, with guidance for using the tools
safely: close rather than delete, confirm destructive calls, never handle tokens.

## Design

**Credential-less bearer passthrough.** Every tool call forwards the caller's
`Authorization: Bearer <token>` (a personal API token or an OAuth access token) to the Sporfie
API's `/public/**` endpoints, which authenticate and authorize it. The server holds no secrets
and is a stateless protocol adapter (`stateless_http=True`, so it scales horizontally). The
three Help Center tools never receive the caller's credential, because published Zendesk
articles are public.

**Two authentication modes.** With OAuth on (`SPORFIE_MCP_OAUTH_ISSUER` set, as at
mcp.sporfie.com), every MCP request without a Bearer token gets an HTTP 401 discovery challenge
before it is dispatched: that includes `tools/list` and the Help Center tools. With OAuth off
(the default, for example a local run), nothing is challenged: listing tools and the Help
Center tools work anonymously, and each API tool needs the header. A script or probe that
connects anonymously must therefore target an OAuth-off instance, or present a token.

**Tool arguments are untrusted.** An agent can be steered by content it read elsewhere, so:

- values that end up in a URL path must be plain Sporfie keys (letters, digits, `-`, `_`), are
  percent-encoded, and the final URL is compared with the tool's own template before sending;
- responses are never decompressed (a compressed answer is refused), are read under a byte cap
  and a total deadline, and upstream admission is bounded (see Limits);
- error bodies reach the agent only as an allowlist of safe fields with internals scrubbed out;
  a body that cannot be shown becomes a generic message with a short reference. The log line holds
  the reference, the status and the size, never the body: redaction cannot be trusted to catch every
  credential an upstream echoes back;
- every failure is an MCP tool error (`isError: true`), never a successful result;
- tools carry MCP annotations (read-only, destructive, idempotent, open-world), so clients can
  ask the user before a destructive call. The API still authorizes every call.

| File | Role |
|---|---|
| `src/sporfie_public_server/server.py` | FastMCP app: 19 tools, `/health`, ASGI `app` |
| `paths.py` | validation of every tool argument that becomes part of a request |
| `auth.py` | the one place the `Authorization` header is read: Bearer scheme, exactly one header |
| `client.py` | Sporfie API client: auth passthrough, URL check, uncompressed capped reads, bounded admission, deadline |
| `error_body.py` | allowlist sanitizing of upstream error bodies |
| `help_center.py` | anonymous Zendesk Help Center client (search / article / sections) |
| `rate_limit.py`, `client_ip.py` | per-client-address backstop rate limiter |
| `oauth.py` | OAuth 2.1 resource-server metadata and challenge (off unless configured) |
| `config.py` | environment configuration; the class docstring lists every variable |
| `e2e/` | end-to-end tests of a deployed server, driven the way a client drives it ([e2e/README.md](e2e/README.md)) |
| `PUBLIC_DOC.md` | customer-facing documentation source |
| `.cursor-plugin/plugin.json`, `mcp.json`, `rules/`, `assets/` | the Cursor plugin: manifest, remote server config, agent rule, logo |

## Develop

```bash
uv sync
uv run pytest                                    # offline unit tests
uv run ruff check . && uv run ruff format --check .
uv run python -m sporfie_public_server.server   # serves on :8080, MCP at /mcp
```

Point a local client at it:

```bash
claude mcp add --transport http sporfie-local http://localhost:8080/mcp \
  --header "Authorization: Bearer <token>"
```

## Run the container

```bash
docker buildx build -t sporfie-public-mcp --load .
docker run --rm -p 8080:8080 sporfie-public-mcp
```

The image runs as an unprivileged user and writes nothing at runtime. By default the server
ignores `X-Forwarded-For`. Behind a proxy, set `SPORFIE_MCP_TRUSTED_PROXY_HOPS` to the number of
proxies that append to it, for example 1 behind a single load balancer. Add the public hostname
to `SPORFIE_MCP_ALLOWED_HOSTS`. `config.py` documents the other settings.

### Limits

Every upstream call is bounded, so one slow, huge or hostile response cannot tie the server up.

| Variable | Default | Effect |
|---|---|---|
| `SPORFIE_MCP_MAX_REQUEST_BYTES` | 256 KiB | largest request body; a bigger one gets 413 before it is parsed |
| `SPORFIE_API_MAX_RESPONSE_BYTES` | 2 MiB | bytes read from one upstream response (compressed ones are refused) |
| `SPORFIE_API_TIMEOUT_S` | 30 | HTTP timeout, applied to each phase of a call |
| `SPORFIE_API_DEADLINE_S` | 45 | total time for one upstream call, never below the timeout above |
| `SPORFIE_MCP_MAX_CONCURRENT_UPSTREAM` | 32 | calls in flight per upstream (API and Help Center each) |
| `SPORFIE_MCP_MAX_QUEUED_UPSTREAM` | 64 | calls allowed to wait for a slot; the next one fails as "busy" |
| `SPORFIE_MCP_QUEUE_TIMEOUT_S` | 5 | longest a call waits for a slot before it fails as "busy" |

Open connections are deliberately not capped in the image. uvicorn's own limit counts idle
keep-alive connections and answers 503 to health checks once it is reached, which would get a
busy pod taken out of rotation. Memory is bounded by the request size above and the admission
limits instead. Put a connection limit in front of the server (a load balancer, a network
policy), not in it.

## Release

`IMAGE_REPOSITORY=<registry>/<repository> ./deployImage.sh` builds and pushes an arm64 image
tagged `{prod|dev}-<sha7>-<version>`. Rolling it out is done in the deployment repository.
Afterwards, run the [end-to-end tests](e2e/README.md) against the rolled-out server: they fail
when it runs another version than this checkout.

## Security

Please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Sporfie. Licensed under the [Apache License, Version 2.0](LICENSE).
