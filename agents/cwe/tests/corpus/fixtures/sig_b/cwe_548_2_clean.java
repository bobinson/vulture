public class FileModule {
    public void register(Router router) {
        // Safe: a single explicit file is served, no directory index handler.
        router.use("/downloads", express.static("/var/www/downloads", indexFalse()));
    }
}
