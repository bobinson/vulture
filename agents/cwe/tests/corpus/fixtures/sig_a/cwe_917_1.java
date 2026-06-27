import org.springframework.expression.ExpressionParser;

public class RuleEngine {
    public Object run(ExpressionParser parser, String request) {
        // CWE-917: SpEL expression assembled from untrusted request input.
        String rule = request;
        return parser.parseExpression("order.total > " + rule).getValue();
    }
}
