public class OgnlEval {
    public Object eval(String request) throws Exception {
        // CWE-917: OGNL expression concatenated from untrusted input.
        String input = request;
        return Ognl.getValue("name == " + input, root);
    }
}
