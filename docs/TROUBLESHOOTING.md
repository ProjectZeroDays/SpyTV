# Troubleshooting Guide

## Common Issues

### C2 Server Won't Start

**Symptom:** `python c2_server.py` exits with error.

**Solutions:**
1. Check Python version: `python --version` (requires 3.8+)
2. Install dependencies: `pip install pyyaml requests colorama`
3. Check port 8443 is not in use: `netstat -ano | findstr 8443`
4. Try a different port: Edit `C2_PORT` in `c2_server.py`

### Devices Not Appearing in Dashboard

**Symptom:** Dashboard shows "No Devices Connected" but exploits were deployed.

**Solutions:**
1. Verify the implant is running on the target device
2. Check that the C2 IP in the payload matches the server's actual IP
3. Ensure no firewall is blocking port 8443 on the C2 server
4. Check browser console on target device for JavaScript errors
5. Verify network connectivity: `ping <c2-ip>` from target

### Network Scan Finds Nothing

**Symptom:** Scan completes but shows no devices.

**Solutions:**
1. Ensure you're on the same network as the target devices
2. Try a broader CIDR range (e.g., `10.0.0.0/8`)
3. Check that your network interface is active
4. Some devices block ICMP — try port scanning instead
5. Verify your IP address: `ipconfig` (Windows) or `ip addr` (Linux)

### Audio/Video Clips Not Appearing

**Symptom:** Clips were recorded but don't show in dashboard.

**Solutions:**
1. Check `c2_data/clips/` directory for files
2. Verify the implant has microphone/camera permissions
3. On Tizen: ensure `tizen:privilege` declarations are in config.xml
4. On webOS: check `appinfo.json` has required access rights
5. Try recording for longer duration (some devices need warm-up time)

### Exploit Deployment Fails

**Symptom:** Payload generates but device doesn't connect back.

**Solutions:**
1. Verify target IP is correct and reachable
2. Check that required ports are open on target (5555 for ADB, etc.)
3. For Samsung TVs: ensure Dev Mode is enabled in settings
4. For LG webOS: ensure Developer Mode app is installed
5. For Android TV: ensure ADB debugging is enabled in Developer Options
6. Check C2 server logs for registration attempts

### SSL/TLS Errors

**Symptom:** `ssl.wrap_socket` or SSL-related errors.

**Solutions:**
1. The C2 uses `ssl.SSLContext` (not deprecated `wrap_socket`)
2. For production: provide valid certificates via `TV_FLOW_KEY` and `TV_FLOW_CERT` env vars
3. For testing: set `C2_USE_SSL=false` to disable SSL
4. Self-signed certs are auto-generated if none found

### Performance Issues

**Symptom:** Dashboard is slow or unresponsive.

**Solutions:**
1. Clear old clips: Delete files in `c2_data/clips/`
2. Clear old logs: Click "Clear Logs" in dashboard
3. Restart C2 server periodically
4. Reduce poll interval on implants (increase `pollIntervalMs`)
5. Close unused browser tabs

## Debug Mode

Set environment variable for verbose output:
```bash
set C2_DEBUG=true
python c2_server.py
```

## Log Files

- C2 Server: `logs/spytv.log`
- Installer: `spytv_install.log`
- Fingerprint: `spytv_fingerprint.log`
- Receiver: `spytv_receiver.log`

## Getting Help

- Check the [Wiki](../README.md) for full documentation
- Review [C2_DASHBOARD.md](./C2_DASHBOARD.md) for dashboard usage
- See [CODE_REVIEW.md](./CODE_REVIEW.md) for known issues
