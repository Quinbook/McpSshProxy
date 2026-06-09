import { contextBridge, ipcRenderer } from 'electron';

contextBridge.exposeInMainWorld('api', {
  // Command approval
  onNewCommand: (callback: (cmd: any) => void) => {
    ipcRenderer.on('new-command', (_event, cmd) => callback(cmd));
  },
  approveCommand: (id: string, host: string, command: string) =>
    ipcRenderer.invoke('approve-command', { id, host, command }),
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
  onOpenServers: (callback: () => void) => {
    ipcRenderer.on('open-servers', () => callback());
  },

  // Misc
  onShowNotification: (callback: (data: any) => void) => {
    ipcRenderer.on('show-notification', (_event, data) => callback(data));
  },
  setAppIcon: (pngDataUrl: string) => ipcRenderer.send('set-app-icon', pngDataUrl),
});
