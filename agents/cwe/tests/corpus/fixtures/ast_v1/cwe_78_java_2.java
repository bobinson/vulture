// Pins: new ProcessBuilder("sh", "-c", "ls " + dir).start() where dir := request.getParameter("dir"); positional -c flag on the ProcessBuilder sink.
class ListingService {
    Process listing(HttpServletRequest request) throws IOException {
        String dir = request.getParameter("dir");
        return new ProcessBuilder("sh", "-c", "ls " + dir).start();
    }
}
