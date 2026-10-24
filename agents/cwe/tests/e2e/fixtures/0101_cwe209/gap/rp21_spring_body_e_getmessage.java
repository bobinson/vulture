class Ctl {
  ResponseEntity<String> get() {
    try { run(); } catch (Exception e) {
      // EXPECT-NEXT: clean  known-gap spring body e getMessage
      return ResponseEntity.status(500).body(e.getMessage());
    }
    return null;
  }
}
