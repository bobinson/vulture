import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;

public class DenyServe {
    private static final Set<String> HIDDEN = Set.of("secrets.properties", "web.xml");

    public byte[] serve(HttpServletRequest request) throws Exception {
        String name = request.getParameter("name");
        String file = HIDDEN.contains(name) ? "index.html" : name;
        return Files.readAllBytes(Path.of("/srv/static", file)); // EXPECT: finding check=cwe.input_validation.path_traversal
    }
}
