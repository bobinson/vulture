public record Outcome(bool Ok, string Error);

public class Ctl : ControllerBase
{
    private Outcome Load(string id)
    {
        try
        {
            return new Outcome(true, null);
        }
        catch (Exception ex)
        {
            return new Outcome(false, ex.Message);
        }
    }

    public async Task Get(HttpContext ctx, string id)
    {
        var o = Load(id);
        await ctx.Response.WriteAsync(o.Error); // EXPECT: finding tp-cs-K
    }
}
