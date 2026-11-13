import * as fs from "fs";
import * as path from "path";
import express from "express";

class Layout {
  private readonly root = "/srv/shards";
  hash = (name: string) => path.join(this.root, name);
}

const layout = new Layout();
export const app = express();
app.get("/shard", (req, res) => {
  res.send(fs.readFileSync(layout.hash(String(req.query.name)))); // EXPECT: finding check=cwe.input_validation.path_traversal
});
