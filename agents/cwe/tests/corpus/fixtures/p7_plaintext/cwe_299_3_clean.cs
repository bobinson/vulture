using System.Net.Http;

public static class HandlerFactory
{
    public static HttpClientHandler Build()
    {
        var handler = new HttpClientHandler();
        handler.CheckCertificateRevocationList = true;
        return handler;
    }
}
