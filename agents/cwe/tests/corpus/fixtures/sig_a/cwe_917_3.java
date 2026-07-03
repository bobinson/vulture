import org.springframework.expression.spel.standard.SpelExpressionParser;

public class FilterCompiler {
    public Object compile(String request) {
        // CWE-917: SpEL expression formatted from untrusted input.
        SpelExpressionParser parser = new SpelExpressionParser();
        String input = request;
        return parser.parseExpression("item.tag == " + input).getValue();
    }
}
