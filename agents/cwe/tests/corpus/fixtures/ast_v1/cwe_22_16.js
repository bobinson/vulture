// pins: a four-line fs.readFile( call reports one row at its first line; its argument lines raise no sibling path row
function handler(req) {
  fs.readFile(
    path.join("/srv/docs", req.query.f),
    "utf8",
    () => {});
}
