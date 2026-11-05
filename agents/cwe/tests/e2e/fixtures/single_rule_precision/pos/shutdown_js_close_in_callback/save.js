// The stream is closed only when it errors.
function save(p, rows) {
  // EXPECT-NEXT: finding
  const out = fs.createWriteStream(p);
  out.on("error", () => out.close());
  for (const row of rows) {
    out.write(row);
  }
}

module.exports = { save };
