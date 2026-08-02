import jakarta.ejb.Stateless;

@Stateless
public class BatchRunner {
  public void run(Batch batch) {
    if (batch.isFatal()) {
      Runtime.getRuntime().halt(1);
    }
  }
}
