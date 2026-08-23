import java.util.Random;

public class Issuer {
  public String issue() {
    String secret = Long.toHexString(new Random().nextLong());
    return secret;
  }
}
