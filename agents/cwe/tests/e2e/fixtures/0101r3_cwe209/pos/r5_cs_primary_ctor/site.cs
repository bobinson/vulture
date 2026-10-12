public class Outcome(bool ok, string? error)
{
    public bool Ok { get; } = ok;
    public string? Error { get; } = error;
}
public class Api
{
    static Outcome Load(string id)
    {
        try { Store.Read(id); return new Outcome(true, null); }
        catch (Exception e) { return new Outcome(false, e.Message); }
    }
    public IResult Show(string id)
    {
        var o = Load(id);
        if (!o.Ok) return Results.Json(new { error = o.Error }); // EXPECT: finding tp-cs-primary-ctor-results
        return Results.Ok();
    }
}
