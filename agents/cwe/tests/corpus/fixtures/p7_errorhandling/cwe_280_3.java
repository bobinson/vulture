public class PolicyLoader {
  public byte[] load(String name) {
    try {
      return readRestricted(name);
    } catch (SecurityException e) {}
    return new byte[0];
  }
}
