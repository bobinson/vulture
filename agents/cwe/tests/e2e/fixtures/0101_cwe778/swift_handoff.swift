// Feature 0101, CWE-778 Swift implicit `error` binding. Every identifier is invented.
final class Reader {
    var lastError: Error?

    func readPage(_ url: URL) -> Data? {
        do {
            return try Data(contentsOf: url)
        } catch { // EXPECT: clean
            self.lastError = error
            return nil
        }
    }

    func unseal(_ box: AES.GCM.SealedBox) -> Data? {
        do {
            return try AES.GCM.open(box, using: key)
        } catch { // EXPECT: finding
            self.lastError = error
            return nil
        }
    }
}
