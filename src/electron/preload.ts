import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('api', {
  // Command approval
  onNewCommand: (callback: (cmd: any) => void) => {
    ipcRenderer.on('new-command', (_event, cmd) => callback(cmd));
  },
  approveCommand: (id: string, host: string, command: string) =>
    ipcRenderer.invoke('approve-command', { id, host, command }),
  approveTransfer: (id: string) => ipcRenderer.invoke('approve-transfer', { id }),
  cancelCommand: (id: string) => ipcRenderer.invoke('cancel-command', { id }),
  sendResult: (id: string, data: any) => ipcRenderer.send('send-result', { id, data }),
  sendError: (id: string, error: string) => ipcRenderer.send('send-error', { id, error }),
  rejectCommand: (id: string, reason: string) => ipcRenderer.send('reject-command', { id, reason }),

  // MCP status
  onMcpStatus: (callback: (status: string) => void) => {
    ipcRenderer.on('mcp-status', (_event, status) => callback(status));
  },
  onMcpClientCount: (callback: (count: number) => void) => {
    ipcRenderer.on('mcp-client-count', (_event, count) => callback(count));
  },

  // Server management
  getServers: () => ipcRenderer.invoke('get-servers'),
  saveServer: (server: any) => ipcRenderer.invoke('save-server', server),
  deleteServer: (id: string) => ipcRenderer.invoke('delete-server', { id }),
  testServer: (id: string) => ipcRenderer.invoke('test-server', { id }),
  pickKeyFile: () => ipcRenderer.invoke('pick-key-file'),
  listPuttySessions: () => ipcRenderer.invoke('list-putty-sessions'),

  // Confirm mode
  getConfirmMode: () => ipcRenderer.invoke('get-confirm-mode'),
  setConfirmMode: (mode: string) => ipcRenderer.invoke('set-confirm-mode', { mode }),

  // Persisted history
  getHistory: () => ipcRenderer.invoke('get-history'),
  addHistory: (entry: any) => ipcRenderer.invoke('add-history', entry),
  clearHistory: (host?: string) => ipcRenderer.invoke('clear-history', { host }),

  // Auto-run command events (auto-list mode)
  onCommandAutostart: (cb: (d: any) => void) => ipcRenderer.on('command-autostart', (_e, d) => cb(d)),
  onCommandAutodone: (cb: (d: any) => void) => ipcRenderer.on('command-autodone', (_e, d) => cb(d)),
  onCommandAutoerror: (cb: (d: any) => void) => ipcRenderer.on('command-autoerror', (_e, d) => cb(d)),

  // Interactive terminal
  termOpen: (sid: string, host: string, cols: number, rows: number) => ipcRenderer.invoke('term-open', { sid, host, cols, rows }),
  termInput: (sid: string, data: string) => ipcRenderer.send('term-input', { sid, data }),
  termResize: (sid: string, cols: number, rows: number) => ipcRenderer.send('term-resize', { sid, cols, rows }),
  termClose: (sid: string) => ipcRenderer.send('term-close', { sid }),
  onTermData: (cb: (d: any) => void) => ipcRenderer.on('term-data', (_e, d) => cb(d)),
  onTermClosed: (cb: (d: any) => void) => ipcRenderer.on('term-closed', (_e, d) => cb(d)),
  onOpenServers: (callback: () => void) => {
    ipcRenderer.on('open-servers', () => callback());
  },

  // Misc
  onShowNotification: (callback: (data: any) => void) => {
    ipcRenderer.on('show-notification', (_event, data) => callback(data));
  },
  setAppIcon: (pngDataUrl: string) => ipcRenderer.send('set-app-icon', pngDataUrl),
});
