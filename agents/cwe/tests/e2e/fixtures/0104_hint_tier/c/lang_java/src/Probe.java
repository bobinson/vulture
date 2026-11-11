import java.io.File;

public class Probe {
    public static boolean present(String filePath) {
        return new File(filePath).exists(); // EXPECT: finding check=cwe.input_validation.path_traversal
    }
}
