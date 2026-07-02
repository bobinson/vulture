public class SpelEval {
    public Object eval(String request) {
        // Safe: constant expression, untrusted input passed as bound variable.
        SpelExpressionParser parser = new SpelExpressionParser();
        StandardEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        ctx.setVariable("input", request);
        return parser.parseExpression("user.name == #input").getValue(ctx);
    }
}
