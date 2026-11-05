// Feature 0101 held-out (LLD 4.6), CWE-209 in Groovy, a language no 0101 probe or
// lexicon touched. Disclosure is the error's message, stack, string form or raw object
// reaching the peer; a fixed text, a code, a type name or a log line is not.
// Every identifier is invented.
// HELD-OUT-TOKENS: HttpExchange, responseBody, sendResponseHeaders, JsonOutput, simpleName, render

class AtlasHandler implements HttpHandler {
    void handle(HttpExchange exchange) {
        try {
            def tile = atlas.lookup(exchange.requestURI.query)
            exchange.sendResponseHeaders(200, 0)
            exchange.responseBody.write(tile.bytes)
        } catch (Exception e) {
            exchange.sendResponseHeaders(500, 0)
            def errorText = "service unavailable"
            // EXPECT-NEXT: clean
            exchange.responseBody.write(errorText.bytes)
        } finally {
            exchange.close()
        }
    }
}
