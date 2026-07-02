public class TokenValidator {
    // Safe: single bounded quantifier, no nesting.
    private static final java.util.regex.Pattern P =
        java.util.regex.Pattern.compile("^[A-Za-z0-9_]{1,64}$");

    public boolean valid(String s) {
        return P.matcher(s).matches();
    }
}
