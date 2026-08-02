public class PolicyLoader {
  public byte[] load(String name) {
    try {
      return readRestricted(name);
    } catch (SecurityException e) {
      throw new PolicyUnavailable(name, e);
    }
  }
}
