package m

func wipe(db X, where string) {
	db.Exec("DELETE FROM a WHERE " + where) // EXPECT: clean
}
