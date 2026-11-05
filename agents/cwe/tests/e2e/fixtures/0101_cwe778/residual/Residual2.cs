// R17 Allman-style forwarding with a return: never recognised (return branch short-circuits)
public class Residual2
{
    public Row? Parse(string s)
    {
        try
        {
            return Row.Parse(s);
        }
        catch (FormatException ex) // EXPECT: clean residual: R17 Allman _errors.Add(ex) + return null
        {
            _errors.Add(ex);
            return null;
        }
    }
}
