// Feature 0101 tuning fixture (round-0 held-out, now tuning): invented identifiers.
public class Payload
{
    public string? ReadPayload(string payload)
    {
        try
        {
            return _protector.Unprotect(payload);
        }
        catch (CryptographicException ex) // EXPECT: finding
        {
            _errors.Add(ex);
            return null;
        }
    }
}
