import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;

public class FilterCompiler {
    public Object compile(String request) {
        // Safe: constant SpEL expression; untrusted input bound via a scoped
        // SimpleEvaluationContext variable instead of string concatenation.
        SpelExpressionParser parser = new SpelExpressionParser();
        SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        ctx.setVariable("input", request);
        return parser.parseExpression("item.tag == #input").getValue(ctx);
    }
}
