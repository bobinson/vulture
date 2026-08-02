public class Uploader {
  void send(byte[] blob) {
    try {
      transport.write(blob);
    } catch (Exception e) {
      logger.warn("upload failed", e);
    }
  }
}
