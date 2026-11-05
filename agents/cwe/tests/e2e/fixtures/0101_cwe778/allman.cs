// Feature 0101, CWE-778 Allman bodies (RED778-6): the Allman and K&R twins of a
// handler get the same verdict. Every identifier is invented.
public class SheetReader
{
    public string? ReadSheet(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (IOException ex) // EXPECT: clean
        {
            _errors.Add(ex);
            return null;
        }
    }

    public string? ReadSheetKr(string path) {
        try {
            return File.ReadAllText(path);
        } catch (IOException ex) { // EXPECT: clean
            _errors.Add(ex);
            return null;
        }
    }

    public string? ReadSealed(string payload)
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

    public string? ReadSealedKr(string payload) {
        try {
            return _protector.Unprotect(payload);
        } catch (CryptographicException ex) { // EXPECT: finding
            _errors.Add(ex);
            return null;
        }
    }
}
