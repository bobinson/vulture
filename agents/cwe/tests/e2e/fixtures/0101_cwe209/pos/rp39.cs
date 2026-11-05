public class H {
    public async Task Invoke(HttpContext context) {
        try { await svc.Load(); } catch (Exception ex) {
            // EXPECT-NEXT: finding
            await context.Response.WriteAsync(ex.Message);
        }
    }
}
