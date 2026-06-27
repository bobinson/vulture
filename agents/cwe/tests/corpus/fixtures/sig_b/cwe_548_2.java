public class FileModule {
    public void register(Router router) {
        // CWE-548: serveIndex handler mounted, exposing the directory contents.
        router.use("/downloads", serveIndex("/var/www/downloads"));
    }
}
