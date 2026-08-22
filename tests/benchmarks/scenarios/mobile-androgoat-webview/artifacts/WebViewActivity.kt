package owasp.sat.agoat

class WebViewXSSActivity {
    fun setup(web: WebView) {
        web.settings.javaScriptEnabled = true          // setJavaScriptEnabled(true)
        // VULN: native object exposed to arbitrary web JS over cleartext (CWE-749)
        web.addJavascriptInterface(NativeBridge(this), "android")
        web.loadUrl("http://androgoat.example/promo.html")  // remote + http
    }
    class NativeBridge(val ctx: Context) {
        @JavascriptInterface fun readFile(p: String): String = File(p).readText()
    }
}
