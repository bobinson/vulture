import com.google.common.collect.Sets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class Purge {
    public void delete(HttpServletRequest request) throws Exception {
        for (String name : Sets.newArrayList(request.getParameterValues("file"))) {
            Files.deleteIfExists(Paths.get("/srv/crates", name)); // EXPECT: finding check=cwe.input_validation.path_traversal
        }
    }
}
