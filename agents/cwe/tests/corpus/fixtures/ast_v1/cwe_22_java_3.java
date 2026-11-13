// pins: 0104 WS-D - newHashSet is a word, not the exact `hash` key: the request values a set copies still reach Paths.get (positive)
import com.google.common.collect.Sets;
import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServletRequest;

public class CratePurge {
    public void delete(HttpServletRequest request) throws Exception {
        for (String name : Sets.newHashSet(request.getParameterValues("file"))) {
            Files.deleteIfExists(Paths.get("/srv/crates", name));
        }
    }
}
