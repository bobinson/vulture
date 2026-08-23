import javax.crypto.spec.PBEKeySpec;

public class Kdf {
  public byte[] derive(char[] password, byte[] salt) throws Exception {
    PBEKeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
    return spec.getEncoded();
  }
}
