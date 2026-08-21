import javax.crypto.spec.PBEKeySpec;

public class Kdf {
  public byte[] derive(char[] password) throws Exception {
    PBEKeySpec spec = new PBEKeySpec(password, "a1b2c3d4".getBytes("UTF-8"), 65536, 256);
    return spec.getEncoded();
  }
}
