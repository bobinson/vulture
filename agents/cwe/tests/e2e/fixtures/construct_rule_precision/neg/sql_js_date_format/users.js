function touch(db, moment, id) {
  return db.query("UPDATE t SET seen = ? WHERE id = ?", [moment().format("YYYY-MM-DD"), id]); // EXPECT: clean
}
