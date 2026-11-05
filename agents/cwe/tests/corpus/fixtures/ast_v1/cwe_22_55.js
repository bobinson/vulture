// pins: optional chaining with a nullish default - req?.query?.f ?? "index" joins the external request field with a constant, so the external origin still reaches fs.readFile
function handler(req, res) {
  const f = req?.query?.f ?? "index";
  fs.readFile(f, (err, data) => res.end(data));
}
app.get("/doc", handler);
