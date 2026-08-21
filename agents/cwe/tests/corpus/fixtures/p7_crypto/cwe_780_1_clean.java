package example;

public final class Sealer {
    public byte[] seal(PublicKey pub, byte[] msg) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        return cipher.doFinal(msg);
    }
}
