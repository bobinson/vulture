using System.Security.Cryptography.X509Certificates;

public static class ChainFactory
{
    public static X509Chain Build()
    {
        var chain = new X509Chain();
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        return chain;
    }
}
