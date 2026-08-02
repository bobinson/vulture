import java.security.SecureRandom;

public class Issuer {
  public String apiKey() {
    SecureRandom rng = new SecureRandom();
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < 24; i++) out.append((char) ('a' + rng.nextInt(26)));
    return out.toString();
  }
}
