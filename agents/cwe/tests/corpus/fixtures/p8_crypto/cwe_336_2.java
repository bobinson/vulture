import java.util.Random;

public class Issuer {
  public String apiKey() {
    Random rng = new Random(987654321L);
    StringBuilder out = new StringBuilder();
    for (int i = 0; i < 24; i++) out.append((char) ('a' + rng.nextInt(26)));
    return out.toString();
  }
}
