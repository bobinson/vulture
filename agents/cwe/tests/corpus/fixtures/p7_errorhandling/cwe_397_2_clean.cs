class Ledger {
  void Commit(int entry) {
    if (entry < 0) {
      throw new ArgumentOutOfRangeException(nameof(entry));
    }
    Flush(entry);
  }
}
