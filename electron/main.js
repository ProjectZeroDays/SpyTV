// SpyTV C2 — Electron main process (CommonJS)
'use strict';

const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const { spawn } = require('child_process');
const { URL } = require('url');

const CHECK_URL = 'http://127.0.0.1:8443/api/local_ip';
const CHECK_TIMEOUT_MS = 2000;
const OFFLINE_RECHECK_MS = 15000;
const SERVER_STARTUP_MS = 3000;  // grace period before first health check

let mainWindow = null;
let serverProcess = null;        // child_process for c2_server.py
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
    let timer = null;
    const done = (value) => {
      if (settled) return;
      settled = true;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      resolve(value);
    };

    const { net } = require('electron');
    let req;
    try {
      req = net.request({ method: 'GET', url: CHECK_URL });
    } catch (_) {
      return done(false);
    }

    timer = setTimeout(() => {
      try { req.abort(); } catch (_) {}
      done(false);
    }, timeoutMs);

    req.on('response', (res) => {
      res.resume();
      done(true);
    });
    req.on('error', () => done(false));
    req.on('abort', () => done(false));

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
      mainWindow.webContents.send('server-status', { online: true });
      // Let the renderer set the iframe src — keep index.html as the container.
    }
  }, OFFLINE_RECHECK_MS);
}

// ---------------------------------------------------------------------------
// C2 server process management
// ---------------------------------------------------------------------------
function spawnC2Server() {
  const fs = require('fs');

  // Resolve the repo root — in dev it's one level up from electron/,
  // in a packaged exe the Python files are bundled via extraResources.
  const candidates = [
    path.resolve(__dirname, '..'),            // dev: electron/ → repo root
    path.resolve(__dirname, '..', '..'),       // packaged: resources/ → repo root
    process.cwd(),                            // fallback: current working dir
  ];

  let repoRoot = null;
  for (const c of candidates) {
    if (fs.existsSync(path.join(c, 'c2_server.py'))) {
      repoRoot = c;
      break;
    }
  }
  if (!repoRoot) repoRoot = path.resolve(__dirname, '..');

  const pythonExe = process.env.SPYTV_PYTHON || 'python';
  const serverScript = path.join(repoRoot, 'c2_server.py');

  // Prefer venv python if available
  const venvPython = path.join(repoRoot, 'venv', 'Scripts', 'python.exe');
  const pythonBin = fs.existsSync(venvPython) ? venvPython : pythonExe;

  const args = ['-u', serverScript];  // -u for unbuffered output

  try {
    const proc = spawn(pythonBin, args, {
      cwd: repoRoot,
      windowsHide: false,
      env: { ...process.env, SPYTV_C2_PORT: '8443' },
    });

    proc.stdout.on('data', (data) => {
      const text = data.toString('utf8');
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('server-output', text);
      }
    });

    proc.stderr.on('data', (data) => {
      const text = data.toString('utf8');
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('server-output', text);
      }
    });

    proc.on('error', (err) => {
      const msg = `[ERROR] Failed to start C2 server: ${err.message}\n`;
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('server-output', msg);
        mainWindow.webContents.send('server-status', { online: false, error: err.message });
      }
    });

    proc.on('exit', (code, signal) => {
      const msg = `[C2 server exited with code ${code} (${signal || 'no signal'})]\n`;
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('server-output', msg);
        mainWindow.webContents.send('server-status', { online: false });
      }
      serverProcess = null;
    });

    serverProcess = proc;
    return proc;
  } catch (err) {
    const msg = `[ERROR] Could not spawn C2 server: ${err.message}\n`;
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('server-output', msg);
    }
    return null;
  }
}

function killC2Server() {
  if (serverProcess && serverProcess.pid) {
    try {
      serverProcess.kill();
    } catch (_) {}
  }
  serverProcess = null;
}

// ---------------------------------------------------------------------------
// App lifecycle
// ---------------------------------------------------------------------------
async function loadApp() {
  if (!mainWindow || mainWindow.isDestroyed()) return false;

  // Give the server a moment to start, then check
  await new Promise(r => setTimeout(r, SERVER_STARTUP_MS));
  const up = await checkServer();

  if (mainWindow.isDestroyed()) return false;

  if (up) {
    stopOfflineRecheck();
    mainWindow.webContents.send('server-status', { online: true });
    // Load the dashboard in the iframe via the renderer
    mainWindow.loadFile(path.join(__dirname, 'index.html'));
  } else {
    startOfflineRecheck();
    mainWindow.loadFile(path.join(__dirname, 'index.html'));
  }
  return up;
}

// ---------------------------------------------------------------------------
// IPC handlers
// ---------------------------------------------------------------------------
ipcMain.handle('retry', async () => {
  try {
    return await loadApp();
  } catch (err) {
    console.error('retry failed:', err);
    return false;
  }
});

ipcMain.handle('get-server-info', async () => ({
  python: process.versions.node,
  electron: process.versions.electron,
  chrome: process.versions.chrome,
  app: app.getVersion(),
}));

ipcMain.handle('restart-server', () => {
  killC2Server();
  const proc = spawnC2Server();
  return proc ? true : false;
});

ipcMain.handle('kill-server', () => {
  killC2Server();
  return true;
});

// Window controls for frameless window
ipcMain.on('window:minimize', () => {
  if (mainWindow) mainWindow.minimize();
});
ipcMain.on('window:maximize', () => {
  if (mainWindow) {
    if (mainWindow.isMaximized()) mainWindow.unmaximize();
    else mainWindow.maximize();
  }
});
ipcMain.on('window:close', () => {
  if (mainWindow) mainWindow.close();
});
ipcMain.on('window:start-drag', (event) => {
  // Allow dragging the frameless window (CSS -webkit-app-region handles the
  // common case; this is a fallback for elements marked no-drag).
  const win = BrowserWindow.fromWebContents(event.sender);
  if (win && typeof win.startMove === 'function') win.startMove();
});

ipcMain.handle('window:is-maximized', () => {
  if (mainWindow) return mainWindow.isMaximized();
  return false;
});

// ---------------------------------------------------------------------------
// Boot
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

  app.whenReady().then(async () => {
    // Minimal, safe menu on Windows (Ctrl+C / Ctrl+V etc. keep working via roles).
    if (process.platform === 'win32' || process.platform === 'linux') {
      const { Menu } = require('electron');
      Menu.setApplicationMenu(null);
    }

    createWindow();

    // Spawn the C2 server as a child process (self-contained app)
    spawnC2Server();

    // Wait for server to be ready, then load the app
    loadApp().catch((err) => console.error('loadApp failed:', err));
  });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1366,
    height: 820,
    minWidth: 1000,
    minHeight: 640,
    backgroundColor: '#0B1220',
    title: 'SpyTV C2',
    frame: false,           // frameless — custom title bar
    titleBarStyle: 'hidden',
    trafficLightPosition: { x: 16, y: 16 },
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });

  // Safety net: show window even if server takes a while
  const showGuard = setTimeout(() => {
    if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.isVisible()) {
      mainWindow.show();
      mainWindow.focus();
    }
  }, 10000);

  mainWindow.once('ready-to-show', () => {
    clearTimeout(showGuard);
    if (mainWindow && !mainWindow.isDestroyed()) mainWindow.show();
  });

  // Deny popups; open http(s) links in the default browser.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:/i.test(url)) {
      shell.openExternal(url).catch(() => {});
    }
    return { action: 'deny' };
  });

  // Keep navigation inside the local dashboard
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
    killC2Server();
    mainWindow = null;
  });
}

// Allow self-signed TLS certs only on loopback (local C2 server).
app.on('certificate-error', (event, webContents, url, error, certificate, callback) => {
  if (isLoopbackUrl(url)) {
    event.preventDefault();
    callback(true);
  } else {
    callback(false);
  }
});

app.on('window-all-closed', () => {
  stopOfflineRecheck();
  killC2Server();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
    spawnC2Server();
    loadApp().catch((err) => console.error('loadApp failed:', err));
  }
});

// Clean up child process on app exit
app.on('before-quit', () => {
  stopOfflineRecheck();
  killC2Server();
});
