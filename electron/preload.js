// SpyTV C2 — preload script
// Keeps contextIsolation intact: exposes only non-sensitive info plus the
// retry IPC used by the offline fallback page.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('spytv', {
  versions: {
    electron: process.versions.electron,
    chrome: process.versions.chrome,
    node: process.versions.node,
    app: '1.0.2'
  },
  // Ask the main process to re-check the local C2 server and reload.
  retry: () => ipcRenderer.invoke('retry')
});
