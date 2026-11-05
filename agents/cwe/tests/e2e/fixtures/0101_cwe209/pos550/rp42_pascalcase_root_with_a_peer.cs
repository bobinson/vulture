public class Page {
    public void Load() {
        try {
            Run();
        } catch (Exception ex) {
            // EXPECT-NEXT: finding check=cwe.info_exposure.server_error_message  PascalCase root with a peer role
            Response.Write(ex.Message);
        }
    }
}
