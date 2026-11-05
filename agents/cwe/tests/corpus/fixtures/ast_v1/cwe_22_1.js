// pins: two-statement flow in one handler - req.query.f is bound to p, then fs.readFile(p) is the sink
function handler(req) { const p = req.query.f; fs.readFile(p); }
app.use("/doc", handler);
