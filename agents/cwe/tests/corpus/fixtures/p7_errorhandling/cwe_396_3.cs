class Importer {
  void Load(string path) {
    try {
      Parse(path);
    } catch (SystemException e) {
      Log.Warn(e);
    }
  }
}
