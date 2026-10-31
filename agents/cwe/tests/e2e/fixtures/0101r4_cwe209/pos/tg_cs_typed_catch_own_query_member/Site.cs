public class ItemsController {
  public async Task Save(HttpContext context) {
    try { await repo.Save(); } catch (InputValidationException ex) {
      await context.Response.WriteAsync(ex.Query); // EXPECT: finding tp-cs-own-member-query
    }
  }
}
