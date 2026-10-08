// SpyTV C2 — preload script
// Keeps contextIsolation intact: exposes only non-sensitive info plus the
// IPC channels needed by the renderer for the terminal panel and custom
// frameless window controls.
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('spytv', {
  versions: {
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
    app: '1.1.0'
  },

  // Ask the main process to re-check the local C2 server and reload.
  retry: () => ipcRenderer.invoke('retry'),

  // --- Server lifecycle ---
  getServerInfo: () => ipcRenderer.invoke('get-server-info'),
  restartServer: () => ipcRenderer.invoke('restart-server'),
  killServer: () => ipcRenderer.invoke('kill-server'),

  // --- Event listeners (main -> renderer) ---
  // Terminal output from the C2 server child process
  onServerOutput: (callback) => {
    const listener = (_event, text) => callback(text);
    ipcRenderer.on('server-output', listener);
    return () => ipcRenderer.removeListener('server-output', listener);
  },
  // Server status changes: { online: true } | { online: false, error?: string }
  onServerStatus: (callback) => {
    const listener = (_event, status) => callback(status);
    ipcRenderer.on('server-status', listener);
    return () => ipcRenderer.removeListener('server-status', listener);
  },

  // --- Window controls (frameless / custom chrome) ---
  windowMinimize: () => ipcRenderer.send('window:minimize'),
  windowMaximize: () => ipcRenderer.send('window:maximize'),
  windowClose: () => ipcRenderer.send('window:close'),
  windowStartDrag: () => ipcRenderer.send('window:start-drag'),
  isMaximized: () => ipcRenderer.invoke('window:is-maximized'),
});
