import jakarta.ejb.Stateless;

@Stateless
public class BatchRunner {
  public void run(Batch batch) {
    if (batch.isFatal()) {
      throw new BatchAbortedException(batch.id());
    }
  }
}
