package com.tizen.installer.signing

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import java.net.URLDecoder

/**
 * Full-screen WebView activity for Samsung account OAuth login.
 *
 * The Samsung OAuth flow redirects to `http://localhost:4794/signin/callback?code=<JSON>`.
 * We intercept this redirect in shouldOverrideUrlLoading before the WebView tries to load it.
 */
class SamsungLoginActivity : ComponentActivity() {

    companion object {
        const val EXTRA_AUTH_JSON = "auth_json"
        private const val CALLBACK_URL = "http://localhost:4794/signin/callback"
        private const val STATE_VALUE = "accountcheckdogeneratedstatetext"

        fun buildLoginUrl(): String {
            val encodedCallback = Uri.encode(CALLBACK_URL)
            return "https://account.samsung.com/accounts/be1dce529476c1a6d407c4c7578c31bd/signInGate" +
                    "?locale=&clientId=v285zxnl3h" +
                    "&redirect_uri=$encodedCallback" +
                    "&state=$STATE_VALUE&tokenType=TOKEN"
        }
    }

    private lateinit var webView: WebView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true

            webViewClient = object : WebViewClient() {
                override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                    val url = request.url.toString()
                    return handleUrl(url)
                }

                @Deprecated("Deprecated in Java")
                override fun shouldOverrideUrlLoading(view: WebView, url: String): Boolean {
                    return handleUrl(url)
                }
            }

            loadUrl(buildLoginUrl())
        }

        setContentView(webView)
    }

    private fun handleUrl(url: String): Boolean {
        if (url.startsWith(CALLBACK_URL)) {
            val uri = Uri.parse(url)
            val code = uri.getQueryParameter("code")
            if (!code.isNullOrEmpty()) {
                val decoded = try { URLDecoder.decode(code, "UTF-8") } catch (_: Exception) { code }
                val intent = Intent().putExtra(EXTRA_AUTH_JSON, decoded)
                setResult(RESULT_OK, intent)
                finish()
                return true
            }
            // Handle POST redirect: inject JS to capture form data
            webView.evaluateJavascript("""
                (function() {
                    var forms = document.querySelectorAll('form');
                    for (var i = 0; i < forms.length; i++) {
                        var form = forms[i];
                        var data = new FormData(form);
                        var code = data.get('code');
                        if (code) { window.location.href = '${CALLBACK_URL}?code=' + encodeURIComponent(code); return; }
                    }
                })();
            """, null)
        }
        return false
    }

    override fun onBackPressed() {
        if (webView.canGoBack()) {
            webView.goBack()
        } else {
            setResult(RESULT_CANCELED)
            super.onBackPressed()
        }
    }
}
