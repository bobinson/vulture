using System.Security.Cryptography.X509Certificates;

public static class ChainPolicyFactory
{
    public static X509Chain Build()
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain;
    }
}
