import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;

class Trims {
    void window(BufferedReader r) throws IOException {
        Deque<String> recent = new ArrayDeque<>();
        String line;
        while ((line = r.readLine()) != null) {
            // EXPECT-NEXT: clean removeFirst keeps the window fixed
            recent.addLast(line);
            recent.removeFirst();
        }
    }

    void lines(BufferedReader r) throws IOException {
        StringBuilder sb = new StringBuilder();
        int c;
        while ((c = r.read()) != -1) {
            if (c == '\n') {
                handle(sb.toString());
                sb.setLength(0);
            } else {
                // EXPECT-NEXT: clean setLength(0) resets the builder per line
                sb.append((char) c);
            }
        }
    }

    void handle(String s) {}
}
