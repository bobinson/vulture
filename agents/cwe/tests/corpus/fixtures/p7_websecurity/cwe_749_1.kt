class WebScreen(private val web: WebView) {
    fun attach() {
        web.addJavascriptInterface(NativeBridge(), "native")
    }
}
