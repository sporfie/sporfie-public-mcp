# Security policy

## Reporting a vulnerability

Please report security problems privately, not in a public issue or pull request.

Use GitHub's private vulnerability reporting once it is enabled for this repository: open the
**Security** tab and choose **Report a vulnerability**. Until then, or if you cannot use GitHub,
contact Sporfie support at https://sporfie.zendesk.com/hc/en-us, say that you want to report a
security issue, and we will reply with a private channel. Keep technical details out of that
first message.

A useful report includes:

- what is affected: this server's code, the hosted service at `https://mcp.sporfie.com/mcp`, or
  the Sporfie API behind it;
- steps to reproduce, and the commit or date you tested;
- the impact you expect, and any logs or requests that show it.

We will acknowledge your report, keep you informed while we investigate, and credit you when a
fix ships if you want to be credited.

## Testing guidelines

- Test only with your own Sporfie account, API tokens and data.
- Do not access, change or delete other people's data, and stop as soon as you reach any.
- Do not degrade the service for others: no load testing and no denial-of-service attempts.

## Supported versions

Only the latest release, the latest commit on `main`, receives security fixes to this source
code. If you run your own copy, update to the latest `main`.

The hosted service at `https://mcp.sporfie.com/mcp` is operated by Sporfie and may run the
previous release for a short time after a new one is published. To see which version is running,
read `serverInfo.version` in the response to the MCP `initialize` request.
