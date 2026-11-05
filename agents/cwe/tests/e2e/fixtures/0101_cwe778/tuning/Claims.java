// Feature 0101 tuning fixture (round-0 held-out, now tuning): invented identifiers.
public class Claims {
  private Exception lastError;
  public Optional<Body> readClaims(String raw) {
    try {
      return Optional.of(Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(raw).getBody());
    } catch (JwtException e) { // EXPECT: finding
      this.lastError = e;
      return Optional.empty();
    }
  }

  // E8 TLS peer-trust failure collected into a list
  private boolean peerTrusted(X509Certificate[] chain) {
    try {
      trustManager.checkServerTrusted(chain, "RSA");
      return true;
    } catch (CertificateException ce) { // EXPECT: finding
      failures.add(ce);
      return false;
    }
  }
}
