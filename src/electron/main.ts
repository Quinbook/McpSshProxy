import { app, BrowserWindow, ipcMain, Notification, safeStorage, nativeImage } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import Store from 'electron-store';
import { Client as SshClient, ConnectConfig } from 'ssh2';

interface ServerConfig {
  id: string;
  name: string;
  host: string;
  port: number;
  user: string;
  authType: 'key' | 'password' | 'agent';
  keyPath?: string;
  passwordEnc?: string;    // base64 safeStorage ciphertext
  passphraseEnc?: string;  // base64 safeStorage ciphertext
}

const store = new Store({
  defaults: {
    servers: [] as ServerConfig[],
  },
});

// Single-instance lock — prevents multiple Electron windows when several MCP processes race to spawn one.
if (!app.requestSingleInstanceLock()) {
  process.exit(0);
}

process.on('uncaughtException', (err: any) => {
  if (err && err.code === 'EADDRINUSE') {
    process.stderr.write(`[MCP] Port ${WS_PORT} already in use — exiting silently.\n`);
    app.exit(0);
    return;
  }
  process.stderr.write(`[MCP] Uncaught exception: ${err?.message || err}\n`);
});

const WS_PORT = 52346;

let mainWindow: BrowserWindow | null = null;

// Tracks running commands -> their ssh2 client, so we can abort them.
const runningConns = new Map<string, SshClient>();

// Maps command/request ID to the WebSocket client that sent it.
const requestToClient = new Map<string, WebSocket>();
const mcpClients = new Set<WebSocket>();

// --- safeStorage helpers ---
function encryptSecret(plain: string): string {
  if (!plain) return '';
  if (!safeStorage.isEncryptionAvailable()) {
    // Fallback: store as-is prefixed so we know it's not encrypted. Should not happen on Windows.
    return 'plain:' + Buffer.from(plain, 'utf8').toString('base64');
  }
  return 'enc:' + safeStorage.encryptString(plain).toString('base64');
}

function decryptSecret(enc?: string): string {
  if (!enc) return '';
  if (enc.startsWith('plain:')) {
    return Buffer.from(enc.slice(6), 'base64').toString('utf8');
  }
  if (enc.startsWith('enc:')) {
    return safeStorage.decryptString(Buffer.from(enc.slice(4), 'base64'));
  }
  return '';
}

function getServers(): ServerConfig[] {
  return (store.get('servers') as ServerConfig[]) || [];
}

function findServer(name: string): ServerConfig | undefined {
  const lower = name.toLowerCase();
  return getServers().find(s => s.name.toLowerCase() === lower);
}

// --- Helper: send messages to specific MCP client ---
function ws_sendResult(client: WebSocket, id: string, data: any) {
  client.send(JSON.stringify({ type: 'result', id, data }));
  requestToClient.delete(id);
}

function ws_sendError(client: WebSocket, id: string, error: string) {
  client.send(JSON.stringify({ type: 'error', id, error }));
  requestToClient.delete(id);
}

function ws_sendRejected(client: WebSocket, id: string, reason: string) {
  client.send(JSON.stringify({ type: 'rejected', id, reason }));
  requestToClient.delete(id);
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    title: 'MCP SSH Proxy',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));

  mainWindow.webContents.on('did-finish-load', () => {
    const clientCount = mcpClients.size;
    mainWindow?.webContents.send('mcp-status', clientCount > 0 ? 'connected' : 'disconnected');
    mainWindow?.webContents.send('mcp-client-count', clientCount);

    if (getServers().length === 0) {
      mainWindow?.webContents.send('open-servers');
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// --- SSH execution ---
function buildConnectConfig(server: ServerConfig): ConnectConfig {
  const cfg: ConnectConfig = {
    host: server.host,
    port: server.port || 22,
    username: server.user,
    readyTimeout: 20000,
    keepaliveInterval: 10000,
  };

  if (server.authType === 'password') {
    cfg.password = decryptSecret(server.passwordEnc);
  } else if (server.authType === 'key') {
    if (!server.keyPath) throw new Error('No private key path configured for this server.');
    cfg.privateKey = fs.readFileSync(server.keyPath);
    const passphrase = decryptSecret(server.passphraseEnc);
    if (passphrase) cfg.passphrase = passphrase;
  } else if (server.authType === 'agent') {
    cfg.agent = process.env.SSH_AUTH_SOCK ||
      (process.platform === 'win32' ? '\\\\.\\pipe\\openssh-ssh-agent' : '');
    if (!cfg.agent) throw new Error('No SSH agent socket available (SSH_AUTH_SOCK not set).');
  }

  return cfg;
}

function executeCommand(server: ServerConfig, command: string, id: string): Promise<any> {
  return new Promise((resolve, reject) => {
    let conn: SshClient;
    try {
      conn = new SshClient();
    } catch (e: any) {
      return reject(e);
    }

    let stdout = '';
    let stderr = '';
    let settled = false;

    const done = (fn: () => void) => {
      if (settled) return;
      settled = true;
      runningConns.delete(id);
      try { conn.end(); } catch { /* ignore */ }
      fn();
    };

    conn.on('ready', () => {
      conn.exec(command, { pty: false }, (err, stream) => {
        if (err) { done(() => reject(err)); return; }

        stream.on('close', (code: number, signal: string) => {
          done(() => resolve({ host: server.name, code, signal, stdout, stderr }));
        });
        stream.on('data', (d: Buffer) => { stdout += d.toString('utf8'); });
        stream.stderr.on('data', (d: Buffer) => { stderr += d.toString('utf8'); });
      });
    });

    conn.on('error', (err) => {
      done(() => reject(err));
    });

    try {
      runningConns.set(id, conn);
      conn.connect(buildConnectConfig(server));
    } catch (e: any) {
      done(() => reject(e));
    }
  });
}

function cancelCommand(id: string): { success: boolean; error?: string } {
  const conn = runningConns.get(id);
  if (!conn) {
    return { success: false, error: 'Command not currently running (or already finished).' };
  }
  try {
    conn.end();
    return { success: true };
  } catch (e: any) {
    return { success: false, error: e.message };
  }
}

// --- WebSocket Server (accepts connections from MCP processes) ---
function startWebSocketServer() {
  const httpServer = http.createServer((req, res) => {
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  const wss = new WebSocketServer({ server: httpServer });

  wss.on('connection', (ws) => {
    mcpClients.add(ws);
    process.stderr.write(`[MCP] MCP client connected (total: ${mcpClients.size})\n`);
    mainWindow?.webContents.send('mcp-status', 'connected');
    mainWindow?.webContents.send('mcp-client-count', mcpClients.size);

    ws.on('message', (data) => {
      try {
        const msg = JSON.parse(data.toString());

        if (msg.type === 'list_hosts') {
          // No approval needed — just report the configured hosts (no secrets).
          const hosts = getServers().map(s => ({
            host: s.name,
            address: s.host,
            port: s.port || 22,
            user: s.user,
            auth: s.authType,
          }));
          ws.send(JSON.stringify({ type: 'result', id: msg.id, data: hosts }));
          return;
        }

        if (msg.type === 'command') {
          requestToClient.set(msg.id, ws);

          mainWindow?.webContents.send('new-command', {
            id: msg.id,
            host: msg.host,
            command: msg.command,
            description: msg.description,
          });
          mainWindow?.flashFrame(true);
          if (mainWindow?.isMinimized()) mainWindow.restore();
          mainWindow?.focus();

          mainWindow?.webContents.send('show-notification', {
            title: 'MCP SSH Proxy',
            body: msg.description || `Neuer Befehl für ${msg.host} wartet auf Freigabe`,
          });
        }
      } catch (e) {
        console.error('Failed to parse MCP message:', e);
      }
    });

    ws.on('close', () => {
      mcpClients.delete(ws);
      process.stderr.write(`[MCP] MCP client disconnected (total: ${mcpClients.size})\n`);
      mainWindow?.webContents.send('mcp-client-count', mcpClients.size);
      if (mcpClients.size === 0) {
        mainWindow?.webContents.send('mcp-status', 'disconnected');
      }
      for (const [reqId, client] of requestToClient) {
        if (client === ws) requestToClient.delete(reqId);
      }
    });
  });

  httpServer.on('error', (err: any) => {
    if (err.code === 'EADDRINUSE') {
      process.stderr.write(`[MCP] Port ${WS_PORT} already in use — another Electron instance is probably running. Exiting.\n`);
      app.exit(0);
    } else {
      process.stderr.write(`[MCP] HTTP server error: ${err.message}\n`);
    }
  });

  httpServer.listen(WS_PORT, '127.0.0.1', () => {
    process.stderr.write(`[MCP] WebSocket server listening on port ${WS_PORT}\n`);
  });
}

// --- IPC Handlers ---

ipcMain.handle('approve-command', async (_event, { id, host, command }) => {
  const server = findServer(host);
  if (!server) {
    return { success: false, error: `No server named "${host}" is configured.` };
  }
  try {
    const result = await executeCommand(server, command, id);
    return { success: true, data: result };
  } catch (e: any) {
    return { success: false, error: e.message };
  }
});

ipcMain.handle('cancel-command', async (_event, { id }) => {
  return cancelCommand(id);
});

ipcMain.on('send-result', (_event, { id, data }) => {
  const client = requestToClient.get(id);
  if (client && client.readyState === WebSocket.OPEN) {
    ws_sendResult(client, id, data);
  }
});

ipcMain.on('send-error', (_event, { id, error }) => {
  const client = requestToClient.get(id);
  if (client && client.readyState === WebSocket.OPEN) {
    ws_sendError(client, id, error);
  }
});

ipcMain.on('reject-command', (_event, { id, reason }) => {
  const client = requestToClient.get(id);
  if (client && client.readyState === WebSocket.OPEN) {
    ws_sendRejected(client, id, reason);
  }
});

// --- Server management ---
// Returned to the renderer WITHOUT decrypted secrets — only a flag whether one is stored.
ipcMain.handle('get-servers', () => {
  return getServers().map(s => ({
    id: s.id,
    name: s.name,
    host: s.host,
    port: s.port,
    user: s.user,
    authType: s.authType,
    keyPath: s.keyPath || '',
    hasPassword: !!s.passwordEnc,
    hasPassphrase: !!s.passphraseEnc,
  }));
});

ipcMain.handle('save-server', (_event, incoming: any) => {
  const servers = getServers();
  const idx = incoming.id ? servers.findIndex(s => s.id === incoming.id) : -1;
  const existing = idx >= 0 ? servers[idx] : undefined;

  // Generate a stable id without Math.random / Date.now collisions across saves.
  const id = incoming.id || `srv_${servers.length + 1}_${process.hrtime.bigint().toString(36)}`;

  const server: ServerConfig = {
    id,
    name: (incoming.name || '').trim(),
    host: (incoming.host || '').trim(),
    port: parseInt(incoming.port) || 22,
    user: (incoming.user || '').trim(),
    authType: incoming.authType || 'key',
    keyPath: (incoming.keyPath || '').trim() || undefined,
    // Empty password/passphrase field => keep the previously stored secret (blank = unchanged).
    passwordEnc: incoming.password ? encryptSecret(incoming.password) : existing?.passwordEnc,
    passphraseEnc: incoming.passphrase ? encryptSecret(incoming.passphrase) : existing?.passphraseEnc,
  };

  if (!server.name) return { success: false, error: 'Name is required.' };
  if (!server.host) return { success: false, error: 'Host is required.' };
  if (!server.user) return { success: false, error: 'User is required.' };

  // Names must be unique (they are the handle ssh_exec uses).
  const clash = servers.find(s => s.id !== id && s.name.toLowerCase() === server.name.toLowerCase());
  if (clash) return { success: false, error: `Another server already uses the name "${server.name}".` };

  if (idx >= 0) servers[idx] = server;
  else servers.push(server);

  store.set('servers', servers);
  return { success: true, id };
});

ipcMain.handle('delete-server', (_event, { id }) => {
  const servers = getServers().filter(s => s.id !== id);
  store.set('servers', servers);
  return { success: true };
});

ipcMain.handle('test-server', async (_event, { id }) => {
  const server = getServers().find(s => s.id === id);
  if (!server) return { success: false, error: 'Server not found.' };
  try {
    const result = await executeCommand(server, 'echo ssh-proxy-ok', `test_${id}`);
    if (result.code === 0 && /ssh-proxy-ok/.test(result.stdout)) {
      return { success: true };
    }
    return { success: false, error: `Unexpected response (code ${result.code}): ${result.stderr || result.stdout}` };
  } catch (e: any) {
    return { success: false, error: e.message };
  }
});

ipcMain.on('set-app-icon', (_event, pngDataUrl: string) => {
  try {
    const img = nativeImage.createFromDataURL(pngDataUrl);
    mainWindow?.setIcon(img);
  } catch (e: any) {
    process.stderr.write(`[MCP] Set icon error: ${e.message}\n`);
  }
});

// --- App lifecycle ---
app.setAppUserModelId('com.woizzer.mcp-ssh-proxy');

app.on('second-instance', () => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
  }
});

app.whenReady().then(() => {
  createWindow();
  startWebSocketServer();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});
