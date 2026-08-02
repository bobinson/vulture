using System.Security.Cryptography;

public static class Sealer
{
    public static byte[] Seal(RSA key, byte[] message)
    {
        return key.Encrypt(message, RSAEncryptionPadding.OaepSHA256);
    }
}
