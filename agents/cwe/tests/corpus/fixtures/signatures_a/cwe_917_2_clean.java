public class OgnlEval {
    public Object eval(String request) throws Exception {
        // Safe: constant OGNL expression; request never concatenated.
        return Ognl.getValue("name == 'guest'", root);
    }
}
