public class Api
{
    public void Show(string id)
    {
        try
        {
            Store.Read(id);
        }
        catch (Exception e)
        {
            ResultsLog.Write(e.Message); // EXPECT: clean a-log-type-is-not-the-peer
        }
    }
}
