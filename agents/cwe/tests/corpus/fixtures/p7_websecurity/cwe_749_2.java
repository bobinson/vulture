public class WebScreen {
    void attach(WebView web) {
        web.addJavascriptInterface(new NativeBridge(), "native");
    }
}
