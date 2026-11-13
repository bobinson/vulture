import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import java.util.TreeMap;
import javax.servlet.http.HttpServletRequest;

public class Reader {
    public byte[] read(HttpServletRequest request) throws Exception {
        Map<String, String[]> params = new TreeMap<>(request.getParameterMap());
        String name = params.get("file")[0];
        return Files.readAllBytes(Paths.get("/srv/vault", name)); // EXPECT: finding check=cwe.input_validation.path_traversal
    }
}
