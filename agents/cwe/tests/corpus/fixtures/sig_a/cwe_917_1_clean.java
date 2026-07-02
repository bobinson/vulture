import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class RuleEngine {
    public Object run(ExpressionParser parser, String request) {
        // Safe: scoped SimpleEvaluationContext; untrusted input bound as a variable.
        SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        ctx.setVariable("rule", request);
        return parser.parseExpression("order.total > #rule").getValue(ctx);
    }
}
