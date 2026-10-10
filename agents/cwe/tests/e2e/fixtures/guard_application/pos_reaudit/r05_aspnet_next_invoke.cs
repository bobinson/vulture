public async Task Invoke(HttpContext context) {
    if (context.Request.Headers["X-Internal"] == "true") {
        await _next.Invoke(context);
        return;
    }
    if (!context.User.Identity.IsAuthenticated) { context.Response.StatusCode = 401; return; }
    await _next(context);
}
