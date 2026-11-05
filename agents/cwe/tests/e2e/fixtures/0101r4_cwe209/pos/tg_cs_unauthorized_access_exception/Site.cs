public class FilesController {
    public void Read(HttpResponse response, string name) {
        try {
            System.IO.File.ReadAllText(name);
        } catch (UnauthorizedAccessException ex) {
            response.Write(ex.Message); // EXPECT: finding tp-cs-unauthorized-access-names-a-path
        }
    }
}
