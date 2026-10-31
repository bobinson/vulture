import java.io.*;
import java.math.BigDecimal;
import java.util.*;
import java.util.concurrent.ArrayBlockingQueue;

public class Bounded {
    List<String> split(String text) throws IOException {
        List<String> lines = new ArrayList<>();
        BufferedReader br = new BufferedReader(new StringReader(text));
        String line;
        while ((line = br.readLine()) != null) {
            // EXPECT-NEXT: clean F18 reader over an in-memory string
            lines.add(line);
        }
        return lines;
    }

    BigDecimal sum(BufferedReader in) throws IOException {
        BigDecimal total = BigDecimal.ZERO;
        String line;
        while ((line = in.readLine()) != null) {
            // EXPECT-NEXT: clean F19 arithmetic .add on a scalar
            total = total.add(new BigDecimal(line));
        }
        return total;
    }

    void handOff(InputStream in, ArrayBlockingQueue<byte[]> q) throws Exception {
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) {
            // EXPECT-NEXT: finding known-gap: bounded queue declared outside the routine (LLD 5.2.6) (probe:F20 ArrayBlockingQueue.put blocks when full)
            q.put(Arrays.copyOf(buf, n));
        }
    }

    Map<String, String> lru(BufferedReader in, Map<String, String> cache) throws IOException {
        // cache is a LinkedHashMap with removeEldestEntry -> bounded
        String line;
        while ((line = in.readLine()) != null) {
            // EXPECT-NEXT: finding known-gap: LRU-bounded map declared outside the routine (LLD 5.2.6) (probe:F21 put into an LRU-bounded map)
            cache.put(line, line);
        }
        return cache;
    }
}
