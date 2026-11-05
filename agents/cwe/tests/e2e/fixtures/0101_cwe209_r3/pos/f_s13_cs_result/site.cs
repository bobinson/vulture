public class LedgerEndpoint {
    static Outcome Load(string id) {
        try { Store.Read(id); return new Outcome(); }
        catch (Exception ex) { return new Outcome { Error = ex.Message }; }
    }
    public async Task Show(HttpContext context, string id) {
        var outcome = Load(id);
        await context.Response.WriteAsync(outcome.Error); // EXPECT: finding tp
    }
}
