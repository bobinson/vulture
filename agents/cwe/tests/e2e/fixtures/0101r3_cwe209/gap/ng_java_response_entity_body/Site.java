class ItemController {
    ResponseEntity<String> get(String id) {
        try { return ResponseEntity.ok(store.read(id)); }
        catch (Exception ex) { return ResponseEntity.status(500).body(ex.getMessage()); } // EXPECT: clean gap-NG-builder-body
    }
}
