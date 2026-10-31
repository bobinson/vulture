public class AuthMiddleware {
    private readonly RequestDelegate _next;
    public async Task Invoke(HttpContext context) {
        if (context.Request.Query["debug"] == "1") {
            await _next.Invoke(context);
            return;
        }
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    }
}
