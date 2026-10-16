public class Api
{
    public IResult Show(string id)
    {
        try
        {
            Store.Read(id);
            return Results.Ok();
        }
        catch (Exception e)
        {
            Logger.LogError(e, "read failed");
            return Results.Json(new { error = "READ_FAILED" }); // EXPECT: clean literal-code
        }
    }
}
