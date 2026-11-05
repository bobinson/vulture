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
            return Results.Json(new { error = e.Message }); // EXPECT: finding tp-cs-results-factory-catch
        }
    }
}
