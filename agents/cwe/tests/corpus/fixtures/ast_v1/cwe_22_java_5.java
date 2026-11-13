// pins: 0104 WS-C - Java is outside the rule: a locate helper probes Paths.get(BASE, fileName) (positive)
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class LedgerStore {
    private static final String BASE = "/var/app/ledgers";

    public Path find(String fileName) {
        Path p = Paths.get(BASE, fileName);
        if (!Files.exists(p)) {
            throw new IllegalArgumentException("no such ledger");
        }
        return p;
    }
}
