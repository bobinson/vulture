public class TemplateEvaluator {
    public Object eval(String request) {
        // Safe: constant compiled expression; untrusted input supplied as a
        // bound variable in the value map, never concatenated into the source.
        Object compiled = MVEL.compileExpression("amount >= threshold");
        java.util.Map<String, Object> vars = new java.util.HashMap<>();
        vars.put("threshold", request);
        return MVEL.executeExpression(compiled, vars);
    }
}
