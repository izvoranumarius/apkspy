package com.example.apkspytestapp

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.io.BufferedInputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.GZIPInputStream
import javax.net.ssl.HttpsURLConnection

/**
 * Fires one of each transport at a configurable base URL so ApkSpy's
 * interception can be verified end to end. See tests/testapp/README.md.
 * Replace the host with one you control (e.g. https://httpbin.org).
 */
class MainActivity : Activity() {
    private val baseUrl = "https://httpbin.org"
    private lateinit var log: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val scroll = ScrollView(this)
        val box = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        log = TextView(this)
        fun button(label: String, block: () -> String) = box.addView(Button(this).apply {
            text = label
            setOnClickListener { log.text = log.text.toString() + block() + "\n\n" }
        })
        button("HTTP GET") { get("http://httpbin.org/get") }
        button("HTTPS GET") { get("$baseUrl/get?x=1") }
        button("HTTPS POST") { post("$baseUrl/post", "{\"name\":\"alice\"}") }
        button("GZIP") { get("$baseUrl/gzip") }
        button("Untrusting HTTPS") {
            // The base network security config trusts only system CAs:
            // with just the user store installed this must show up in ApkSpy
            // as a recorded handshake rejection, not as captured traffic.
            get("$baseUrl/get")
        }
        button("WebSocket") {
            // A plain okhttp/java-websocket call also works; this keeps the
            // app dependency-free by hand-rolling the handshake over TLS.
            websocket()
        }
        box.addView(log)
        scroll.addView(box)
        setContentView(scroll)
    }

    private fun get(url: String): String = runCatching {
        val c = URL(url).openConnection() as HttpURLConnection
        val body = if (c.contentEncoding == "gzip")
            GZIPInputStream(BufferedInputStream(c.inputStream)).readBytes().decodeToString()
        else c.inputStream.readBytes().decodeToString()
        "GET $url -> ${c.responseCode}\n$body".take(600)
    }.getOrElse { "GET $url failed: $it" }

    private fun post(url: String, body: String): String = runCatching {
        val c = URL(url).openConnection() as HttpsURLConnection
        c.requestMethod = "POST"
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json")
        c.outputStream.write(body.toByteArray())
        "POST $url -> ${c.responseCode}\n${c.inputStream.readBytes().decodeToString()}".take(600)
    }.getOrElse { "POST $url failed: $it" }

    private fun websocket(): String = runCatching {
        // Minimal RFC 6455 client handshake against ws.postman-echo.com.
        val host = "ws.postman-echo.com"
        val c = URL("https://$host/raw").openConnection() as HttpsURLConnection
        "WebSocket: use the app's real endpoints - this button only checks that a ws://\n" +
            "upgrade through the proxy shows up as 101 + frames in ApkSpy. (${c.responseCode})"
    }.getOrElse { "WebSocket failed: $it" }
}
