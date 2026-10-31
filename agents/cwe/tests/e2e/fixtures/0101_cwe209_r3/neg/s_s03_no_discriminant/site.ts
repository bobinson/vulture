export async function rows(req, res) {
  for await (const row of cursor) {
    res.write(row.error); // EXPECT: clean clean-S-no-discriminant
  }
}
