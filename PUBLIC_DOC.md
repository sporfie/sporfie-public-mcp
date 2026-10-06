# Sporfie MCP — connect your AI agent to Sporfie

> Customer-facing documentation source. Keep in sync with the tools in
> `server.py`; suitable for pasting into the Zendesk Help Center or the
> developer pages on sporfie.com.

The Sporfie MCP server lets AI agents — Claude Code, Claude apps, Cursor, or
anything that speaks the [Model Context Protocol](https://modelcontextprotocol.io)
— work with your Sporfie events, highlight clips, venues and live streams, and
answer support questions from our Help Center.

- **Endpoint**: `https://mcp.sporfie.com/mcp` (Streamable HTTP)
- **Authentication**: sign in through your client (OAuth, no token to copy), or send your
  personal Sporfie API token as `Authorization: Bearer <token>`
- **Tools**: 19

## Quick start

### Cursor, Claude and other clients with OAuth sign-in

Add `https://mcp.sporfie.com/mcp` as a remote MCP server and sign in with your Sporfie account
when your client asks. There is no token to create or paste.

### Claude Code with a personal API token

1. Create a token at **https://sporfie.com/settings/developer**.
   It is shown once — copy it right away. You can revoke it there at any time.
2. Add the server:

   ```bash
   claude mcp add --transport http sporfie https://mcp.sporfie.com/mcp --header "Authorization: Bearer YOUR_TOKEN"
   ```

3. Ask away: *"list my Sporfie places"*, *"create a football event for
   tomorrow 18:00 on Field 1"*, *"my camera isn't showing — search the help
   center"*.

### Clients without OAuth sign-in

Any client that supports remote MCP servers with custom headers can send the token instead:

```json
{
  "mcpServers": {
    "sporfie": {
      "type": "http",
      "url": "https://mcp.sporfie.com/mcp",
      "headers": { "Authorization": "Bearer YOUR_TOKEN" }
    }
  }
}
```

Claude API (MCP connector — both halves plus the beta header are required):

```json
{
  "mcp_servers": [
    { "type": "url", "url": "https://mcp.sporfie.com/mcp", "name": "sporfie",
      "authorization_token": "YOUR_TOKEN" }
  ],
  "tools": [ { "type": "mcp_toolset", "mcp_server_name": "sporfie" } ]
}
```

(with request header `anthropic-beta: mcp-client-2025-11-20`)

## Authentication & scope

**Signing in.** The hosted server asks you to sign in before it answers
anything. A request without a Bearer token gets an HTTP 401 that tells the
client where to sign in (an OAuth discovery challenge), and that includes
listing the tools and the three Help Center tools. A client with OAuth support
follows the challenge and signs you in through your browser. A client without
it sends a personal API token instead, in exactly one
`Authorization: Bearer <token>` header.

**What you can do.** Your sign-in or token acts **as you**: it can read and
manage content in the companies where you are an admin, and that is checked on
every single call by the Sporfie backend — the MCP server stores nothing and
grants nothing by itself. Revoking the token, or losing company membership,
takes effect immediately. The three Help Center tools read public articles and
never send your credential anywhere.

**Your own copy.** A copy you run yourself has OAuth off by default: connecting,
listing the tools and the Help Center tools then work without any credential,
and every other tool needs the header.

## Conventions

- **Identifiers** — events are addressed by their Sporfie `eventKey` *or* by
  the `externalID` you chose when creating them through the API. Keys and
  externalIDs contain only letters, digits, `-` and `_` (an externalID has at
  most 64 characters); anything else is rejected before a request is made.
- **Times** are epoch **milliseconds** (UTC).
- **Event states** are `future` (scheduled), `current` (running), `past`.
- **Updates are PATCH-style**: only the fields you send change.
- **Errors are tool errors** — failed calls come back as MCP tool errors
  carrying the Sporfie API's status and its error fields (`HTTP <status>: {"code":…,"message":…}`),
  so the agent sees the real reason. For a server-side failure (5xx) the details stay on the
  server: you get a generic message with a short *Reference* id, which support can look up.
  If the server is busy, the call fails with "The server is busy; retry shortly." — retry
  after a few seconds.
- **Confirmations** — every tool is annotated as read-only or not, and
  destructive tools (update, close, delete, webhook changes) are marked as
  such, so your MCP client can ask you before running them.
- **Rate limits** — the API allows roughly 1 request/second per token (`429`,
  back off); the MCP endpoint additionally throttles by client IP.
- Large responses are truncated with a marker — narrow the query to see more.

## Tool reference

Every tool except the Help Center ones acts as you, with your sign-in or API token, and is
checked by the Sporfie backend on every call.

### Events

| Tool | Signature | What it does |
|---|---|---|
| `get_event` | `(event_key_or_external_id)` | Public projection of one event: name, teams, sport, times, state, streaming/clip info. |
| `create_event` | `(external_id, event)` | Create an event. `event` supports `companyKey` (required), `name`, `description`, `sport`, `placeKey`, `scheduledStartTime`/`scheduledEndTime`/`announcedTime`/`announcedDuration`/`startTime` (epoch ms), `homeTeam`, `awayTeam`, `location {name, geoLoc{lat,lng}}`, `thumbnailURL`, `pinCode`, `cameraPinCode`, `notSearchable`, `metadata`, `disableSporfieWatermark`. Returns the new `eventKey`. |
| `update_event` | `(event_key_or_external_id, patch)` | Change fields of an event (same field names as create). |
| `close_event` | `(event_key_or_external_id)` | End a running event now (stops recording/streaming). Only for events created by your API identity. Not idempotent: calling it again re-sets the end time to the new "now". |
| `delete_event` | `(event_key_or_external_id)` | Permanently delete an event. Irreversible. |

### Discovery

| Tool | Signature | What it does |
|---|---|---|
| `search_events` | `(company_key, state="current", page_size=20, page=0)` | List a company's events by state, paged (`page_size` 1–100). |
| `lookup_event_by_place_and_time` | `(place_key, year, month, day, hour)` | Which event was live on a place at that local date + hour. |
| `get_active_event_key` | `(place_key)` | The event currently live on a place, if any. |
| `list_places` | `(company_key)` | A company's venues / camera locations and their `placeKey`s. |
| `list_sports` | `()` | Valid sport identifiers for events. |

### Moments (highlight clips)

| Tool | Signature | What it does |
|---|---|---|
| `register_click` | `(event_key_or_external_id, timestamp_ms, metadata?)` | Cut a highlight clip ("moment") around an absolute timestamp inside an event. Returns the `momentKey`. |
| `get_moment` | `(moment_key)` | One moment: event, timing, video URLs, metadata. |
| `update_moment` | `(moment_key, patch)` | Update a moment, e.g. replace its `metadata`. |
| `delete_moment` | `(moment_key)` | Permanently delete a moment. Irreversible. |

### Webhooks

| Tool | Signature | What it does |
|---|---|---|
| `watch_event` | `(event_key_or_external_id, webhook_url)` | Subscribe an HTTPS webhook to an event's lifecycle/content updates. One watch per event per API identity — calling again replaces it. |
| `unwatch_event` | `(event_key_or_external_id)` | Remove your webhook from an event. |

### Support (Help Center)

These read the public Help Center and need no Sporfie permissions; your credential is never
sent to it.

| Tool | Signature | What it does |
|---|---|---|
| `search_help_center` | `(query, locale="en-us", page=1)` | Search the Sporfie Help Center (how-tos, troubleshooting, known issues). |
| `get_help_article` | `(article_id, locale="en-us")` | Read one Help Center article in full, with its public URL. |
| `list_help_center_sections` | `(locale="en-us")` | Browse the Help Center's category/section tree. |

## Support

Can't find an answer with the Help Center tools? Contact Sporfie support at
[https://sporfie.zendesk.com/hc/en-us](https://sporfie.zendesk.com/hc/en-us).
