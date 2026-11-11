const fs = require("fs");
const crypto = require("crypto");
const app = require("express")();
app.get("/a", (req, res) => {
  const id = crypto.createHmac("sha256", "k").update(req.query.email).digest();
  fs.writeFile("/srv/" + id + ".pdf", "", () => {}); // EXPECT: finding check=cwe.input_validation.path_traversal
});
