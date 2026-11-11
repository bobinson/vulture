import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;
import javax.servlet.http.HttpServletRequest;

public class Blobs {
    static final String ROOT = "/srv/blobs";

    public byte[] byKey(HttpServletRequest request) throws IOException {
        int key = Objects.hash(request.getParameter("name"), request.getParameter("kind"));
        return Files.readAllBytes(Paths.get(ROOT, key + ".bin")); // EXPECT: clean check=cwe.input_validation.path_traversal
    }
}
