public class AuthMiddleware {
    public async Task InvokeAsync(HttpContext context) {
        if (context.Request.Headers["X-Internal"] == "true") {
            await _next(context);
            return;
        }
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }
}
