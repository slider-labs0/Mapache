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
