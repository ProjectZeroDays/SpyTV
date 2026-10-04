package com.authenticated.spytv

import android.app.AlertDialog
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.io.IOException
import java.io.Reader
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.URL

/**
 * SpyTV Android console.
 *
 * The C2 dashboard is NOT served on the phone, so "localhost" here would be the
 * phone itself — historically that sent this WebView to whatever else happened
 * to own port 8443 on the device, and the user saw that program's raw JSON
 * instead of the dashboard. The endpoint is therefore configurable, and every
 * load is verified first: if the answer isn't the SpyTV dashboard we say so and
 * show what came back rather than rendering it as if it were ours.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var webView: WebView
    private lateinit var errorView: View
    private lateinit var errorTitle: TextView
    private lateinit var errorDetail: TextView
    private lateinit var btnRetry: Button
    private lateinit var btnAddress: Button
    private lateinit var btnSettings: Button

    private val prefs by lazy { getSharedPreferences(PREFS, MODE_PRIVATE) }
    private var c2Url: String = DEFAULT_URL

    /** Text that only the real dashboard contains (its <title>). */
    private val dashboardMarker = "TV Security Assessment Platform"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        webView = findViewById(R.id.webView)
        errorView = findViewById(R.id.errorView)
        errorTitle = findViewById(R.id.errorTitle)
        errorDetail = findViewById(R.id.errorDetail)
        btnRetry = findViewById(R.id.btnRetry)
        btnAddress = findViewById(R.id.btnAddress)
        btnSettings = findViewById(R.id.btnSettings)

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

        val saved = prefs.getString(KEY_URL, null)
        c2Url = saved?.takeIf { it.isNotBlank() } ?: DEFAULT_URL

        btnRetry.setOnClickListener { open(c2Url) }
        btnAddress.setOnClickListener { promptForAddress() }
        btnSettings.setOnClickListener { promptForAddress() }

        if (saved.isNullOrBlank()) {
            // First run: ask where the C2 lives instead of guessing.
            promptForAddress()
        } else {
            open(c2Url)
        }
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
                "SpyTV C2 not reachable",
                "Tried: $url\n\n${probe.error}\n\nCheck that:\n" +
                    "  • the C2 is running on that machine  (python c2_server.py)\n" +
                    "  • this device is on the same network as it\n" +
                    "  • the address is the C2 machine's LAN IP, not localhost\n" +
                    "    (on this phone localhost IS this phone)\n" +
                    "  • the firewall allows the C2 port"
            )
            !probe.isSpyTV -> showError(
                "This is not the SpyTV dashboard",
                "Tried: $url\nHTTP ${probe.status}\n\n" +
                    "Something answered, but it is not SpyTV — another program owns\n" +
                    "this address/port, so the console would be talking to the wrong\n" +
                    "thing. The response it returned was:\n\n" +
                    probe.body.ifBlank { "(empty body)" }
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
            .setTitle("SpyTV C2 address")
            .setMessage(
                "Where is the machine running the C2?\n\n" +
                    "Use its LAN IP and port. 'localhost' on this device points at " +
                    "this device, not at the C2."
            )
            .setView(input)
            .setNegativeButton("Cancel", null)
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
        if (webView.visibility == View.VISIBLE && webView.canGoBack()) {
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

    companion object {
        const val PREFS = "spytv_console"
        const val KEY_URL = "c2_url"
        const val DEFAULT_URL = "http://localhost:8443/"
        const val BODY_LIMIT = 8192
    }
}
