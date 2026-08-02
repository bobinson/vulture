import java.security.SecureRandom;

public class Issuer {
  public String issue() {
    String secret = Long.toHexString(new SecureRandom().nextLong());
    return secret;
  }
}
