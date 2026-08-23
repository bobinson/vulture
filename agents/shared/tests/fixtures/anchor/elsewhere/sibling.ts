// sibling.ts -- the quote's actual home, rendered in the same batch.
export function findUser(sql: string) {
  return db.query("SELECT * FROM users WHERE id = " + sql);
}
