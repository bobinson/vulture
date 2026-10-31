// Feature 0101, CWE-778 Concept B in Java. Invented identifiers.
public enum AuthCatalog {
  UNAUTHORIZED(401, "x"), // EXPECT: clean check=cwe.insufficient_logging.auth_decision
  OTHER(500, "y");
  public static final int FORBIDDEN = 403; // EXPECT: clean check=cwe.insufficient_logging.auth_decision
  AuthCatalog(int c, String s) {}
}
