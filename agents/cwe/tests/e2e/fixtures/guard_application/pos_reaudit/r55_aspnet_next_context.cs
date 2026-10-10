app.Use(async (context, next) =>
{
    if (context.Request.Headers["X-Internal"] == "true")
    {
        await next(context);
        return;
    }
    context.Response.StatusCode = 401;
});
