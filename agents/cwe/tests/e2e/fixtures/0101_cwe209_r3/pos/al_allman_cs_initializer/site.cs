public class Outcome { public bool Ok; public string Error; }
public class LedgerEndpoint
{
    static Outcome Load(string id)
    {
        try
        {
            Store.Read(id);
            return new Outcome { Ok = true };
        }
        catch (Exception ex)
        {
            return new Outcome { Ok = false, Error = ex.Message };
        }
    }

    public async Task Show(HttpContext context, string id)
    {
        var outcome = Load(id);
        await context.Response.WriteAsync(outcome.Error); // EXPECT: finding tp-cs-allman-initializer
    }
}
