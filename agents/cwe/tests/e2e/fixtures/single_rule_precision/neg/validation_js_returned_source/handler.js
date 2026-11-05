// The reader hands the request value to its caller, which guards it.
function readBody(req) {
  // EXPECT-NEXT: clean
  return req.body.payload;
}

async function handle(req, res) {
  const payload = readBody(req);
  res.set("X-Seen", "1");
  res.status(202);
  res.type("json");
  if (!payload) {
    throw new Error("missing payload");
  }
  res.send("ok");
}

module.exports = { handle };
