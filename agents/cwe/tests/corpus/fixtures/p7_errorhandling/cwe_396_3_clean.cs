class Importer {
  void Load(string path) {
    try {
      Parse(path);
    } catch (FormatException e) {
      Log.Warn(e);
    }
  }
}
