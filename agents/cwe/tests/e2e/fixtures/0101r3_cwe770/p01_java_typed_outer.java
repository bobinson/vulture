import java.util.*;
class R {
    List<String> read(java.io.BufferedReader reader) throws Exception {
        List<String> parts = new ArrayList<>();
        String line;
        while ((line = reader.readLine()) != null) {
            // EXPECT-NEXT: finding typed local declared OUTSIDE the loop outlives it
            parts.add(line);
        }
        return parts;
    }
}
