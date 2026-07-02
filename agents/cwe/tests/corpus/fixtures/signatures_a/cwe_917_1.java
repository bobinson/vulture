public class SpelEval {
    public Object eval(String request) {
        // CWE-917: SpEL expression built from untrusted request input.
        String input = request;
        SpelExpressionParser parser = new SpelExpressionParser();
        return parser.parseExpression("user.name == " + input).getValue();
    }
}
