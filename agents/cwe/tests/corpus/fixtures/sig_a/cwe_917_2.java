public class TemplateEvaluator {
    public Object eval(String request) {
        // CWE-917: MVEL expression compiled from untrusted user payload.
        String payload = request;
        Object compiled = MVEL.compileExpression("amount >= " + payload);
        return MVEL.executeExpression(compiled);
    }
}
