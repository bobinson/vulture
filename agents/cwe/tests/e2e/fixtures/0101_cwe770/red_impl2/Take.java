import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;

class Take {
    void handle(BlockingQueue<String> queue) throws InterruptedException {
        List<String> batch = new ArrayList<>();
        while (true) {
            String m = queue.take();
            // EXPECT-NEXT: finding every message taken from a blocking queue retained
            batch.add(m);
        }
    }
}
