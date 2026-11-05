// Pins: new ProcessBuilder("ls", dir).start() with dir external; argv form with no shell, so no command row through the builder or its start().
class ListingService {
    Process listing(HttpServletRequest request) throws IOException {
        String dir = request.getParameter("dir");
        return new ProcessBuilder("ls", dir).start();
    }
}
