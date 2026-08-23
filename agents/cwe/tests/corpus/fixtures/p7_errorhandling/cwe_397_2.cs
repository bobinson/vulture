class Ledger {
  void Commit(int entry) {
    if (entry < 0) {
      throw new Exception("negative entry");
    }
    Flush(entry);
  }
}
