public class ReposController {
  public async Task Get(HttpContext context, long id) {
    try { await client.Repository.Get(id); } catch (ForbiddenException ex) {
      await context.Response.WriteAsync(ex.Message); // EXPECT: finding tp-cs-outbound-forbidden
    }
  }
}
