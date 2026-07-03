public class MvelEval {
    public Object eval(String request) {
        // CWE-917: MVEL expression built from untrusted user payload.
        String payload = request;
        return MVEL.eval("x > " + payload);
    }
}
