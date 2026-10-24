public class FilesController {
    public void Save(HttpResponse response, string body) {
        try {
            store.Save(body);
        } catch (ValidationException ex) {
            response.Write(ex.InnerException.Message); // EXPECT: finding tp-cs-typed-inner-exception
        }
    }
}
