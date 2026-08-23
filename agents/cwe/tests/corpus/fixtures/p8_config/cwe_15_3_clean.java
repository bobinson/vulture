public class Settings {
  void apply(HttpServletRequest request) {
    System.setProperty("user.timezone", "UTC");
  }
}
