export function wipe(store: Database, req: any): void {
  store.exec("DELETE FROM t WHERE id = " + req.body.id); // EXPECT: finding
}
