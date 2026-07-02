const serveIndex = require("serve-index");
// CWE-548: directory listing explicitly enabled.
app.use("/files", serveIndex("/var/data", { icons: true }));
