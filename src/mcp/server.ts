import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import WebSocket from 'ws';
import { spawn } from 'child_process';
import * as path from 'path';
import * as http from 'http';

const WS_PORT = 52346;

interface PendingRequest {
  id: string;
  resolve: (result: any) => void;
  reject: (error: any) => void;
}

const pendingRequests = new Map<string, PendingRequest>();
let wsClient: WebSocket | null = null;
let requestCounter = 0;
let connectRetries = 0;
const MAX_CONNECT_RETRIES = 10;
let launchInProgress = false;

// --- Check if Electron is already running ---
function isElectronRunning(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:${WS_PORT}/health`, (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on('error', () => resolve(false));
    req.setTimeout(500, () => { req.destroy(); resolve(false); });
  });
}

// --- Launch Electron ---
function launchElectron() {
  const electronPath = path.join(__dirname, '..', '..', 'node_modules', 'electron', 'dist', 'electron.exe');
  const mainPath = path.join(__dirname, '..', 'electron', 'main.js');

  process.stderr.write(`[MCP] Launching Electron: ${electronPath} ${mainPath}\n`);

  const child = spawn(electronPath, [mainPath], {
    stdio: 'ignore',
    detached: true,
  });

  child.on('error', (err) => {
    process.stderr.write(`[MCP] Electron launch error: ${err.message}\n`);
  });

  child.unref();
}

// --- Connect to Electron WebSocket Server ---
function connectToElectron(): Promise<void> {
  return new Promise((resolve, reject) => {
    if (wsClient && wsClient.readyState === WebSocket.OPEN) {
      resolve();
      return;
    }

    const ws = new WebSocket(`ws://127.0.0.1:${WS_PORT}`);

    ws.on('open', () => {
      wsClient = ws;
      connectRetries = 0;
      process.stderr.write('[MCP] Connected to Electron WS server\n');
      resolve();
    });

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());

        if (msg.type === 'result') {
          const pending = pendingRequests.get(msg.id);
          if (pending) {
            pendingRequests.delete(msg.id);
            pending.resolve(msg.data);
          }
        } else if (msg.type === 'error') {
          const pending = pendingRequests.get(msg.id);
          if (pending) {
            pendingRequests.delete(msg.id);
            pending.reject(new Error(msg.error));
          }
        } else if (msg.type === 'rejected') {
          const pending = pendingRequests.get(msg.id);
          if (pending) {
            pendingRequests.delete(msg.id);
            pending.resolve({ rejected: true, reason: msg.reason || 'Command rejected by user' });
          }
        }
      } catch (e) {
        process.stderr.write(`[MCP] Failed to parse message: ${e}\n`);
      }
    });

    ws.on('close', () => {
      wsClient = null;
      process.stderr.write('[MCP] Disconnected from Electron WS server\n');
      setTimeout(() => ensureConnected(), 2000);
    });

    ws.on('error', (err) => {
      process.stderr.write(`[MCP] WS connect error: ${err.message}\n`);
      wsClient = null;
      reject(err);
    });
  });
}

// --- Ensure connection, launching Electron if needed ---
async function ensureConnected(): Promise<void> {
  if (wsClient && wsClient.readyState === WebSocket.OPEN) return;
  if (launchInProgress) return;

  launchInProgress = true;
  try {
    const running = await isElectronRunning();
    if (!running) {
      launchElectron();
      let started = false;
      for (let i = 0; i < 20; i++) {
        await new Promise(r => setTimeout(r, 500));
        if (await isElectronRunning()) { started = true; break; }
      }
      if (!started) {
        process.stderr.write('[MCP] Electron did not start — giving up (port conflict?)\n');
        return;
      }
    }

    await connectToElectron();
  } catch {
    connectRetries++;
    if (connectRetries < MAX_CONNECT_RETRIES) {
      await new Promise(r => setTimeout(r, 2000));
      launchInProgress = false;
      return ensureConnected();
    }
    process.stderr.write('[MCP] Failed to connect to Electron after max retries\n');
  } finally {
    launchInProgress = false;
  }
}

// Send a message to Electron and wait for its matching result/error/rejected reply.
function sendAndWait(message: any): Promise<any> {
  return new Promise(async (resolve, reject) => {
    await ensureConnected();
    pendingRequests.set(message.id, { id: message.id, resolve, reject });
    if (wsClient && wsClient.readyState === WebSocket.OPEN) {
      wsClient.send(JSON.stringify(message));
    } else {
      pendingRequests.delete(message.id);
      reject(new Error('Not connected to SSH Proxy app — could not deliver the command for approval.'));
    }
  });
}

// --- MCP Server ---
const server = new McpServer({
  name: 'ssh-proxy',
  version: '1.0.0',
});

server.tool(
  'ssh_list_hosts',
  'Lists the SSH servers configured in the SSH Proxy desktop app. Returns each host name (the value to pass as `host` to ssh_exec) plus its address and user. No secrets are returned. Call this first to discover which servers you may reach.',
  {},
  async () => {
    const id = `h_${++requestCounter}_${Date.now()}_${process.pid}`;
    try {
      const data = await sendAndWait({ type: 'list_hosts', id });
      return { content: [{ type: 'text', text: JSON.stringify(data, null, 2) }] };
    } catch (e: any) {
      return { content: [{ type: 'text', text: `Error: ${e.message}` }] };
    }
  }
);

server.tool(
  'ssh_exec',
  'Runs a shell command on one of the configured SSH servers. The user reviews and approves (or edits/rejects) the command in the SSH Proxy desktop app before it runs. Returns stdout, stderr and the exit code. Use ssh_list_hosts to discover valid host names.',
  {
    host: z.string().describe('Name of the configured server (as returned by ssh_list_hosts)'),
    command: z.string().describe('The shell command to execute on the server'),
    description: z.string().optional().describe('Brief explanation of why this command is needed'),
  },
  async ({ host, command, description }) => {
    const id = `c_${++requestCounter}_${Date.now()}_${process.pid}`;
    try {
      const data = await sendAndWait({ type: 'command', id, host, command, description });

      if (data?.rejected) {
        return { content: [{ type: 'text', text: `Command was rejected by user: ${data.reason}` }] };
      }

      const code = data?.code;
      const signal = data?.signal;
      const text =
        `host: ${data?.host ?? host}\n` +
        `exit code: ${code}${signal ? ` (signal ${signal})` : ''}\n\n` +
        `--- stdout ---\n${data?.stdout?.length ? data.stdout : '(empty)'}\n\n` +
        `--- stderr ---\n${data?.stderr?.length ? data.stderr : '(empty)'}`;
      return { content: [{ type: 'text', text }] };
    } catch (e: any) {
      return { content: [{ type: 'text', text: `Error: ${e.message}` }] };
    }
  }
);

// --- Start ---
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write('[MCP] SSH Proxy MCP server started\n');

  ensureConnected().catch(() => {});
}

main().catch((e) => {
  process.stderr.write(`[MCP] Fatal: ${e}\n`);
  process.exit(1);
});
