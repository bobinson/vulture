class WebScreen(private val web: WebView) {
    fun attach() {
        web.settings.javaScriptEnabled = false
    }
}
