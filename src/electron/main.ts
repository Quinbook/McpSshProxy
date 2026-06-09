import { app, BrowserWindow, ipcMain, Notification, safeStorage, nativeImage, dialog } from 'electron';
import * as path from 'path';
import * as os from 'os';
import * as fs from 'fs';
import { execFile } from 'child_process';
import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import Store from 'electron-store';
import { Client as SshClient, ConnectConfig } from 'ssh2';
// sshpk has no bundled types; require keeps it as `any` (only parsePrivateKey is used).
// It parses PuTTY .ppk (v2 + v3) directly and re-exports a key ssh2 accepts.
const sshpk = require('sshpk');

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
  // Per-server override of the global confirm mode:
  //   'global' = follow the global setting, 'always' = force approval, 'auto' = never ask (just run/log)
  confirmPolicy?: 'global' | 'always' | 'auto';
}

// 'confirm-each' = every command waits for approval; 'auto-list' = run without asking (just listed).
type ConfirmMode = 'confirm-each' | 'auto-list';

// Use a dedicated app name + userData dir. When run unpackaged (electron dist/...),
// Electron defaults the app name to "Electron", so several such apps would share one
// userData dir AND one single-instance lock — meaning only one could run at a time
// (it killed the sibling SQL proxy). A distinct name gives us our own lock + store.
// Must run BEFORE `new Store()` (Store resolves userData immediately).
app.setName('mcp-ssh-proxy');
try {
  app.setPath('userData', path.join(app.getPath('appData'), 'mcp-ssh-proxy'));
} catch { /* appData may be unavailable in odd environments */ }

const store = new Store({
  defaults: {
    servers: [] as ServerConfig[],
    confirmMode: 'confirm-each' as ConfirmMode,
    history: [] as any[],   // persisted command history (per server, flat list with `host`)
  },
});

// One-time migration: adopt servers previously saved under the shared default userData.
try {
  if (((store.get('servers') as ServerConfig[]) || []).length === 0) {
    const legacy = path.join(app.getPath('appData'), 'Electron', 'config.json');
    if (fs.existsSync(legacy)) {
      const data = JSON.parse(fs.readFileSync(legacy, 'utf8'));
      if (Array.isArray(data.servers) && data.servers.length > 0) {
        store.set('servers', data.servers);
      }
    }
  }
} catch { /* best-effort migration */ }

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

function getConfirmMode(): ConfirmMode {
  return (store.get('confirmMode') as ConfirmMode) || 'confirm-each';
}

// Resolve whether a command on this server must be confirmed: per-server policy wins,
// otherwise fall back to the global mode.
function needsConfirm(server: ServerConfig): boolean {
  const pol = server.confirmPolicy || 'global';
  if (pol === 'always') return true;
  if (pol === 'auto') return false;
  return getConfirmMode() === 'confirm-each';
}

// Persisted, per-server command history (flat list with a `host` field).
function addHistoryEntry(entry: any): void {
  const cap = (s: any) => (typeof s === 'string' && s.length > 10000 ? s.slice(0, 10000) + '\n…(truncated)' : s);
  const hist = (store.get('history') as any[]) || [];
  hist.unshift({ ...entry, stdout: cap(entry.stdout), stderr: cap(entry.stderr) });
  if (hist.length > 1000) hist.length = 1000;
  store.set('history', hist);
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
function isPuttyKey(raw: Buffer): boolean {
  return raw.toString('utf8', 0, 32).startsWith('PuTTY-User-Key-File');
}

// ssh2 only reads OpenSSH/PEM/PKCS#8 keys natively. PuTTY .ppk (v2 and v3/Argon2) is
// detected and converted on the fly so the user never has to convert keys manually.
async function buildConnectConfig(server: ServerConfig): Promise<ConnectConfig> {
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
    const raw = fs.readFileSync(server.keyPath);
    const passphrase = decryptSecret(server.passphraseEnc);
    if (isPuttyKey(raw)) {
      try {
        const key = passphrase
          ? sshpk.parsePrivateKey(raw, 'putty', { passphrase })
          : sshpk.parsePrivateKey(raw, 'putty');
        cfg.privateKey = key.toString('openssh'); // re-export in a format ssh2 accepts
      } catch (e: any) {
        throw new Error(`Could not read PuTTY key (.ppk): ${e.message}`);
      }
    } else {
      cfg.privateKey = raw; // OpenSSH / PEM / PKCS#8 — ssh2 handles these directly
      if (passphrase) cfg.passphrase = passphrase;
    }
  } else if (server.authType === 'agent') {
    cfg.agent = process.env.SSH_AUTH_SOCK ||
      (process.platform === 'win32' ? '\\\\.\\pipe\\openssh-ssh-agent' : '');
    if (!cfg.agent) throw new Error('No SSH agent socket available (SSH_AUTH_SOCK not set).');
  }

  return cfg;
}

async function executeCommand(server: ServerConfig, command: string, id: string): Promise<any> {
  const cfg = await buildConnectConfig(server);
  return new Promise((resolve, reject) => {
    const conn = new SshClient();

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
      conn.connect(cfg);
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
          const server = findServer(msg.host);

          if (server && !needsConfirm(server)) {
            // Auto-run mode: execute immediately, return to the agent, and echo/log in the UI.
            mainWindow?.webContents.send('command-autostart', {
              id: msg.id, host: msg.host, command: msg.command, description: msg.description,
            });
            executeCommand(server, msg.command, msg.id)
              .then((result) => {
                const client = requestToClient.get(msg.id);
                if (client && client.readyState === WebSocket.OPEN) ws_sendResult(client, msg.id, result);
                mainWindow?.webContents.send('command-autodone', { id: msg.id, host: msg.host, command: msg.command, result });
              })
              .catch((err: any) => {
                const client = requestToClient.get(msg.id);
                if (client && client.readyState === WebSocket.OPEN) ws_sendError(client, msg.id, err.message);
                mainWindow?.webContents.send('command-autoerror', { id: msg.id, host: msg.host, command: msg.command, error: err.message });
              });
            return;
          }

          // Confirm mode (or unknown host — still surface it so the user can see/reject).
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

// --- Confirm mode ---
ipcMain.handle('get-confirm-mode', () => getConfirmMode());
ipcMain.handle('set-confirm-mode', (_e, { mode }) => {
  store.set('confirmMode', mode === 'auto-list' ? 'auto-list' : 'confirm-each');
  return true;
});

// --- Persisted history ---
ipcMain.handle('get-history', () => (store.get('history') as any[]) || []);
ipcMain.handle('add-history', (_e, entry) => { addHistoryEntry(entry); return true; });
ipcMain.handle('clear-history', (_e, { host }) => {
  if (!host) store.set('history', []);
  else store.set('history', ((store.get('history') as any[]) || []).filter(h => h.host !== host));
  return true;
});

// --- Interactive shell sessions (xterm terminal, PuTTY-style) ---
const termSessions = new Map<string, { conn: SshClient; stream: any }>();

ipcMain.handle('term-open', async (_e, { sid, host, cols, rows }) => {
  const server = findServer(host);
  if (!server) return { success: false, error: `No server named "${host}" is configured.` };
  try {
    const cfg = await buildConnectConfig(server);
    const conn = new SshClient();
    await new Promise<void>((resolve, reject) => {
      conn.on('ready', () => resolve());
      conn.on('error', (e) => reject(e));
      conn.connect(cfg);
    });
    const stream: any = await new Promise((resolve, reject) => {
      conn.shell({ term: 'xterm-256color', cols: cols || 80, rows: rows || 24 }, (err, s) => err ? reject(err) : resolve(s));
    });
    termSessions.set(sid, { conn, stream });
    stream.on('data', (d: Buffer) => mainWindow?.webContents.send('term-data', { sid, data: d.toString('utf8') }));
    stream.on('close', () => {
      try { conn.end(); } catch { /* ignore */ }
      termSessions.delete(sid);
      mainWindow?.webContents.send('term-closed', { sid });
    });
    return { success: true };
  } catch (e: any) {
    return { success: false, error: e.message };
  }
});

ipcMain.on('term-input', (_e, { sid, data }) => {
  const t = termSessions.get(sid);
  if (t) { try { t.stream.write(data); } catch { /* ignore */ } }
});

ipcMain.on('term-resize', (_e, { sid, cols, rows }) => {
  const t = termSessions.get(sid);
  if (t) { try { t.stream.setWindow(rows, cols, 0, 0); } catch { /* ignore */ } }
});

ipcMain.on('term-close', (_e, { sid }) => {
  const t = termSessions.get(sid);
  if (t) { try { t.stream.end(); t.conn.end(); } catch { /* ignore */ } termSessions.delete(sid); }
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
    confirmPolicy: s.confirmPolicy || 'global',
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
    confirmPolicy: (['global', 'always', 'auto'].includes(incoming.confirmPolicy) ? incoming.confirmPolicy : 'global'),
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

// --- PuTTY session import (Windows registry) ---
function decodePuttyName(raw: string): string {
  try { return decodeURIComponent(raw); } catch { return raw; }
}

function parsePuttyRegDump(out: string): any[] {
  const sessions: any[] = [];
  for (const block of out.split(/\r?\n\r?\n/)) {
    const lines = block.split(/\r?\n/);
    const header = (lines[0] || '').trim();
    if (!/\\Sessions\\/.test(header)) continue;
    const name = decodePuttyName(header.substring(header.lastIndexOf('\\') + 1));

    const vals: Record<string, string> = {};
    for (const line of lines.slice(1)) {
      const m = line.trim().match(/^(\S+)\s+REG_\w+\s+(.*)$/);
      if (m) vals[m[1]] = m[2];
    }

    const host = vals['HostName'] || '';
    if (!host) continue; // skip "Default Settings" and keyless containers

    let port = 22;
    if (vals['PortNumber']) {
      port = vals['PortNumber'].startsWith('0x')
        ? parseInt(vals['PortNumber'], 16)
        : parseInt(vals['PortNumber'], 10);
    }
    const keyPath = vals['PublicKeyFile'] || '';
    sessions.push({
      name,
      host,
      port: port || 22,
      user: vals['UserName'] || '',
      keyPath,
      authType: keyPath ? 'key' : 'password',
    });
  }
  return sessions;
}

function listPuttySessions(): Promise<any[]> {
  return new Promise((resolve) => {
    if (process.platform !== 'win32') return resolve([]);
    execFile(
      'reg',
      ['query', 'HKCU\\Software\\SimonTatham\\PuTTY\\Sessions', '/s'],
      { maxBuffer: 8 * 1024 * 1024, windowsHide: true },
      (err, stdout) => {
        if (err || !stdout) return resolve([]);
        try { resolve(parsePuttyRegDump(stdout)); } catch { resolve([]); }
      }
    );
  });
}

ipcMain.handle('list-putty-sessions', () => listPuttySessions());

ipcMain.handle('pick-key-file', async () => {
  const sshDir = path.join(os.homedir(), '.ssh');
  const result = await dialog.showOpenDialog(mainWindow!, {
    title: 'Select SSH private key',
    defaultPath: fs.existsSync(sshDir) ? sshDir : os.homedir(),
    properties: ['openFile', 'showHiddenFiles'],
    filters: [
      { name: 'SSH keys (OpenSSH, PEM, PuTTY .ppk)', extensions: ['ppk', 'pem', 'key', 'openssh', 'rsa'] },
      { name: 'All files', extensions: ['*'] },
    ],
  });
  if (result.canceled || result.filePaths.length === 0) return '';
  return result.filePaths[0];
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

// Gracefully tear down every SSH connection on normal shutdown (window close / quit),
// so the remote sshd gets a proper disconnect instead of just a dropped socket.
// (On a hard kill this handler can't run; the OS closing the sockets still ends the
// remote sessions, just without a graceful SSH disconnect.)
function closeAllSshConnections() {
  for (const [, t] of termSessions) { try { t.stream.end(); } catch { /* ignore */ } try { t.conn.end(); } catch { /* ignore */ } }
  termSessions.clear();
  for (const [, conn] of runningConns) { try { conn.end(); } catch { /* ignore */ } }
  runningConns.clear();
}

app.on('before-quit', closeAllSshConnections);
process.on('exit', closeAllSshConnections);
process.on('SIGTERM', () => { closeAllSshConnections(); app.quit(); });
process.on('SIGINT', () => { closeAllSshConnections(); app.quit(); });

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
