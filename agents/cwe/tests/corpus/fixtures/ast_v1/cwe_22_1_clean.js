// pins: twin of cwe_22_1.js - path.basename strips directories from req.query.f before fs.readFile(p), so the flow declines
function handler(req) { const p = path.basename(req.query.f); fs.readFile(p); }
app.use("/doc", handler);
