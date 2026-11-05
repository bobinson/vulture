public class Residual {
  // R3 CompletableFuture forwarding
  void run(CompletableFuture<Out> future) {
    try {
      future.complete(compute());
    } catch (Exception e) { // EXPECT: finding known-gap (residual, still reported): R3 future.completeExceptionally(e)
      future.completeExceptionally(e);
    }
  }
}
