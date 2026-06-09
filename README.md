# MCP SSH Proxy

A human-in-the-loop **SSH bridge for AI agents**. It exposes an [MCP](https://modelcontextprotocol.io) server with two tools — `ssh_list_hosts` and `ssh_exec` — but **every command an agent wants to run is held for your review in a desktop app before it touches a server**. You see the exact command and the target host, then click **Run**, edit it, or **Reject** it.

Servers are configured **only in the app's UI** — nothing is hardcoded, and credentials are encrypted at rest with the OS keystore (Windows DPAPI via Electron `safeStorage`).

> Sibling project to [MCP SQL Proxy](https://github.com/) — same approval-loop architecture, applied to SSH instead of SQL.

## Why

Letting an agent run arbitrary shell commands on a production server is risky. This proxy keeps a person in the loop: the agent proposes, you approve. Destructive commands (`rm`, `dd`, `shutdown`, `sudo`, `systemctl stop`, redirects into `/`, …) light the whole window up in **danger mode** so a careless approval is hard.

## Architecture

```
Claude / MCP client ──stdio──► MCP server ──WebSocket(127.0.0.1:52346)──► Electron app
   (ssh_exec)                  (dist/mcp/server.js)                       (approval UI + ssh2)
```

- **MCP server** (`src/mcp/server.ts`) — speaks MCP over stdio, forwards each request to the desktop app and waits for the result. Auto-launches the app if it isn't running.
- **Electron app** (`src/electron/main.ts`) — holds the server list, renders the approval queue, and runs approved commands via [`ssh2`](https://github.com/mscdex/ssh2). Single-instance: many MCP clients share one window.
- **Renderer** (`src/renderer/index.html`) — the UI: server manager + pending-command queue + live output.

Nothing binds to anything but `127.0.0.1`.

## Tools

| Tool | Approval? | Description |
|------|-----------|-------------|
| `ssh_list_hosts` | no | Returns the configured host names (+ address/user/auth). No secrets. Call this first. |
| `ssh_exec` | **yes** | Runs a command on a host (by name). You approve/edit/reject in the app. Returns stdout, stderr, exit code. |

## Install & build

```bash
npm install
npm run build
```

## Run the desktop app standalone

```bash
npm start
```

Open **Servers → + Add** and configure a host:

- **Name** — the handle the agent uses (e.g. `mindhunters3`)
- **User / Host / Port**
- **Authentication** — Private Key (with optional passphrase), Password, or SSH Agent

Hit **Test Connection** to verify. Secrets you type are encrypted before they are stored; the UI never reads them back in clear text (leave a secret field blank when editing to keep the stored value).

## Register as an MCP server

Point your MCP client at the built server entry (`dist/mcp/server.js`). For Claude Code:

```bash
claude mcp add ssh-proxy -- node /absolute/path/to/McpSshProxy/dist/mcp/server.js
```

Or in a client config:

```json
{
  "mcpServers": {
    "ssh-proxy": {
      "command": "node",
      "args": ["/absolute/path/to/McpSshProxy/dist/mcp/server.js"]
    }
  }
}
```

The first `ssh_exec` call auto-launches the approval window.

## Security notes

- All traffic is loopback-only (`127.0.0.1:52346`).
- Passwords and key passphrases are encrypted with the OS keystore (`safeStorage`). On platforms without an available keystore they fall back to obfuscated-but-not-encrypted local storage — prefer key/agent auth there.
- The agent can only target servers **you** have configured by name. An `ssh_exec` for an unknown host is refused.
- This is an approval tool, not a sandbox: once you click **Run**, the command executes with the configured user's privileges. Review before approving.

## License

MIT — see [LICENSE](LICENSE).
