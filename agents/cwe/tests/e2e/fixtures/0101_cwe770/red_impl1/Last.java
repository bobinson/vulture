import java.io.*;
import java.util.*;

class Last {
    void echo(BufferedReader br, PrintWriter pw, Map<String, String> map) throws IOException {
        String line;
        while ((line = br.readLine()) != null) {
            pw.println(line);
            // EXPECT-NEXT: clean constant key: the map holds one entry
            map.put("last", line);
        }
    }
    void index(BufferedReader br, Map<String, Integer> map) throws IOException {
        String line;
        while ((line = br.readLine()) != null) {
            // EXPECT-NEXT: finding a peer-chosen key
            map.put(line, 1);
        }
    }
}
