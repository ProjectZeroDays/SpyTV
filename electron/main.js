// SpyTV C2 — Electron main process (CommonJS)
'use strict';

const { app, BrowserWindow, Menu, shell, ipcMain, net } = require('electron');
const path = require('path');
const { URL } = require('url');

const DASHBOARD_URL = 'http://127.0.0.1:8443/';
const CHECK_URL = 'http://127.0.0.1:8443/api/local_ip';
const CHECK_TIMEOUT_MS = 2000;
const OFFLINE_RECHECK_MS = 15000;

let mainWindow = null;
let offlineTimer = null;
let isOffline = false;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function hostnameOf(url) {
  try {
    return new URL(url).hostname;
  } catch (_) {
    return '';
  }
}

function isLoopbackHost(hostname) {
  return (
    hostname === '127.0.0.1' ||
    hostname === 'localhost' ||
    hostname === '::1' ||
    hostname === '[::1]'
  );
}

function isLoopbackUrl(url) {
  return isLoopbackHost(hostnameOf(url));
}

// Reachability check against the local C2 dashboard API.
function checkServer(timeoutMs = CHECK_TIMEOUT_MS) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    let req;
    try {
      req = net.request({ method: 'GET', url: CHECK_URL });
    } catch (_) {
      return done(false);
    }

    req.on('response', (res) => {
      // Any HTTP response means the server is up (even 401/404).
      res.resume();
      done(true);
    });
    req.on('error', () => done(false));
    req.setTimeout(timeoutMs, () => {
      try {
        req.abort();
      } catch (_) {}
      done(false);
    });

    try {
      req.end();
    } catch (_) {
      done(false);
    }
  });
}

function stopOfflineRecheck() {
  isOffline = false;
  if (offlineTimer) {
    clearInterval(offlineTimer);
    offlineTimer = null;
  }
}

function startOfflineRecheck() {
  if (offlineTimer) return;
  isOffline = true;
  offlineTimer = setInterval(async () => {
    const up = await checkServer();
    if (up && mainWindow && !mainWindow.isDestroyed()) {
      stopOfflineRecheck();
      mainWindow.loadURL(DASHBOARD_URL);
    }
  }, OFFLINE_RECHECK_MS);
}

async function loadApp() {
  if (!mainWindow || mainWindow.isDestroyed()) return false;
  const up = await checkServer();
  if (mainWindow.isDestroyed()) return false;

  if (up) {
    stopOfflineRecheck();
    mainWindow.loadURL(DASHBOARD_URL);
  } else {
    startOfflineRecheck();
    mainWindow.loadFile(path.join(__dirname, 'offline.html'));
  }
  return up;
}

// ---------------------------------------------------------------------------
// IPC (used by offline.html "Retry" button)
// ---------------------------------------------------------------------------
ipcMain.handle('retry', async () => {
  return await loadApp();
});

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(() => {
    // Minimal, safe menu on Windows (Ctrl+C / Ctrl+V etc. keep working via roles).
    if (process.platform === 'win32' || process.platform === 'linux') {
      Menu.setApplicationMenu(null);
    }

    createWindow();
    loadApp();
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 900,
    minHeight: 600,
    backgroundColor: '#0B1220',
    title: 'SpyTV C2 — Authenticated, Inc.',
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  mainWindow.once('ready-to-show', () => {
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.show();
  });

  // Deny popups; open http(s) links in the default browser.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) {
      shell.openExternal(url).catch(() => {});
    }
    return { action: 'deny' };
  });

  // Keep navigation inside the local dashboard (or local fallback page).
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isLoopbackUrl(url) && !url.startsWith('file:')) {
      event.preventDefault();
      if (/^https?:/i.test(url)) {
        shell.openExternal(url).catch(() => {});
      }
    }
  });

  mainWindow.on('closed', () => {
    stopOfflineRecheck();
    mainWindow = null;
  });
}

// Allow the self-signed TLS cert ONLY on loopback (local C2 server).
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (isLoopbackUrl(url)) {
    event.preventDefault();
    callback(true);
  } else {
    callback(false); // never bypass for other hosts
  }
});

app.on('window-all-closed', () => {
  stopOfflineRecheck();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
    loadApp();
  }
});
