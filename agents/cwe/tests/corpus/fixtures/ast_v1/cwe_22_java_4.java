// pins: 0104 WS-D - a HashMap copy of the request parameters is no digest: the copied value reaches Paths.get (positive)
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

public class VaultReader {
    public byte[] read(HttpServletRequest request) throws Exception {
        Map<String, String[]> params = new HashMap<>(request.getParameterMap());
        String name = params.get("file")[0];
        return Files.readAllBytes(Paths.get("/srv/vault", name));
    }
}
