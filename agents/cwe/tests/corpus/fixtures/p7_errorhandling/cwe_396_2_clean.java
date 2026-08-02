public class Uploader {
  void send(byte[] blob) {
    try {
      transport.write(blob);
    } catch (IOException e) {
      logger.warn("upload failed", e);
    }
  }
}
