# MCP and the skill hub

Mapache is extensible in two directions: it consumes tools from Model Context Protocol
servers, and it installs and publishes community skills and tools through a hub.

## MCP client

Mapache connects out to Model Context Protocol servers and exposes their tools as ordinary
Mapache tools. It is a client: Mapache consumes MCP servers, it does not act as one.

### How it works

Each server is launched as a subprocess and spoken to over the stdio transport:
newline-delimited JSON-RPC 2.0 (`initialize`, then `tools/list`, then `tools/call`). A
remote tool is wrapped as a normal tool, registered into the same tool registry and
dispatcher as the built-ins, and namespaced `mcp__<server>__<tool>` to avoid collisions.
Their names are pinned so phase-based subsetting keeps them exposed. Connection is
fail-soft: a bad server never breaks startup, and clients are closed on exit.

### Configuration

Servers are listed in a Claude-Desktop-style `mcp.json` (`--mcp-config`, default
`mcp.json`; absent means MCP is off):

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
      "env": {}
    },
    "fetch": {
      "command": "uvx",
      "args": ["mcp-server-fetch"],
      "env": {}
    }
  }
}
```

The launcher is resolved through PATH, honoring PATHEXT, so a bare command like `npx` or
`uvx` finds its real executable. This is what makes the canonical configuration work on
Windows as well as Linux and macOS.

Note that a third-party MCP server can be broken upstream, independent of Mapache. When
that happens Mapache logs the server as unavailable and continues, rather than failing to
start.

### Driving a browser like a user (Playwright MCP)

The Playwright MCP server lets Mapache drive a real browser the way a person does: it can
navigate, click, type, fill forms, select options, upload files, take screenshots, inspect
network requests, and capture an accessibility snapshot of the page that the model acts on
by element. This is a richer, interactive complement to Mapache's built-in headless
`browser` tool (which renders a page for reading).

Add it to your `mcp.json`:

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest", "--headless"],
      "env": {}
    }
  }
}
```

Its tools appear as `mcp__playwright__browser_navigate`, `mcp__playwright__browser_click`,
`mcp__playwright__browser_snapshot`, `mcp__playwright__browser_type`, and so on (around two
dozen). Notes:

- The first run downloads the package and a browser, so give it a moment.
- Drop `--headless` to watch the browser act (useful for a demo).
- `browser_run_code_unsafe` executes arbitrary JavaScript on the page; only enable this
  server against targets you are authorized to test.
- Mapache looks for `mcp.json` in the working directory you launch from (or the path you
  pass to `--mcp-config`), so put it where you run `mapache serve`.

### Trimming a large server (the tools allowlist)

MCP tools are pinned into every prompt so they stay callable regardless of phase. A server
with two dozen tools therefore inflates the function-calling payload, which can overflow a
local model's context window. Add an optional `"tools"` allowlist to a server so Mapache
exposes only the tools you name:

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": ["-y", "@playwright/mcp@latest", "--headless"],
      "tools": [
        "browser_navigate", "browser_navigate_back", "browser_click", "browser_type",
        "browser_press_key", "browser_fill_form", "browser_snapshot", "browser_find",
        "browser_take_screenshot", "browser_wait_for"
      ]
    }
  }
}
```

Omit `tools` (or leave it empty) to expose every tool the server offers. If a full prompt
still overflows on a small-context model, raise the Ollama window with `OLLAMA_NUM_CTX`
(see [Providers](providers.md)).

### Browsing over Tor (not clearnet Chrome)

To make Mapache browse `.onion` sites and reach the dark web like a user, route the
Playwright browser through Tor instead of the default Chrome channel:

```json
{
  "mcpServers": {
    "playwright": {
      "command": "npx",
      "args": [
        "-y", "@playwright/mcp@latest",
        "--headless", "--isolated",
        "--browser", "chromium",
        "--proxy-server", "socks5://127.0.0.1:9150"
      ],
      "timeout": 90,
      "tools": ["browser_navigate", "browser_click", "browser_type", "browser_snapshot",
                "browser_fill_form", "browser_find", "browser_take_screenshot", "browser_wait_for"]
    }
  }
}
```

Three things make this work:

- `--browser chromium` uses Playwright's bundled Chromium, not Google Chrome. This is what
  "use Playwright, not Chrome" means, and it avoids a "chrome is not found" error on a
  machine without Chrome installed.
- `--proxy-server socks5://127.0.0.1:9150` sends all browser traffic through Tor. Use port
  `9150` if you run the Tor Browser bundle, or `9050` for a system `tor` daemon. Tor must
  be running before you launch Mapache, and Chromium resolves `.onion` hostnames through
  the proxy, so `browser_navigate` reaches onion services.
- `timeout: 90` gives slow Tor page loads room, so a request does not hit the default 30s
  limit and stall.

First run only, install the browser the MCP expects:

```bash
npx @playwright/mcp@latest install-browser chrome-for-testing
```

Verify it is actually exiting through Tor by having the agent navigate to
`https://check.torproject.org` and snapshot the page; it should read
"Congratulations. This browser is configured to use Tor."

## The skill hub

The hub lets you browse, install, and publish reusable extensions. Three manifest types
are supported:

- A generated tool: a self-authored tool packaged for reuse.
- An MCP server: an entry added to your `mcp.json`.
- An external tool: a bring-your-own HTTP or command tool.

### Installing

A hub is configured by pointing at a registry (a local path or an http(s) URL). Installing
a generated tool writes a package to your generated-tools directory and re-verifies its
sha256 before it loads. Installing an MCP server writes an entry into your `mcp.json`. A
tampered package is refused before anything is written. `/hub` and the skill tools drive
this from inside a session, and they degrade gracefully when no hub is configured.

### Publishing

You can publish your own generated tool, MCP server entry, or external tool to a registry,
so a technique that worked for you can be shared with a checksum as the integrity gate.

## Which extension mechanism to use

- Use MCP when you want to reuse an existing tool server that already speaks the protocol.
- Use a self-authored tool when you want the agent to build a small tool on the fly (see
  [Tools](tools.md)).
- Use a skill when you want to teach the agent a technique rather than give it a new tool
  (see [Skills and playbooks](skills-and-playbooks.md)).
- Use the hub to distribute any of these.
