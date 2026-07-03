public class TokenValidator {
    // CWE-1333: nested unbounded quantifier (a+)+ — catastrophic backtracking.
    private static final java.util.regex.Pattern P =
        java.util.regex.Pattern.compile("^(\\w+)+$");

    public boolean valid(String s) {
        return P.matcher(s).matches();
    }
}
