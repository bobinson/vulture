public class MvelEval {
    public Object eval(String request) {
        // Safe: constant compiled expression, no untrusted concatenation.
        return MVEL.eval("x > 10");
    }
}
