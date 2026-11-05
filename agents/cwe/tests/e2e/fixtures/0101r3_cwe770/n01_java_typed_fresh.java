import java.util.*;
class R {
    void read(java.io.BufferedReader reader) throws Exception {
        String line;
        while ((line = reader.readLine()) != null) {
            List<String> parts = new ArrayList<>();
            // EXPECT-NEXT: clean typed local declared in the body lives one iteration
            parts.add(line);
            process(parts);
        }
    }
}
