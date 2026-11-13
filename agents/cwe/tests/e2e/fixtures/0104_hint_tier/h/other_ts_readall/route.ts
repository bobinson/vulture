import express from "express";
import * as fs from "./fs-shim";

const app = express();

app.get("/dump", async (req, res) => {
  const data = await fs.readAll(req.query.p as string); // EXPECT: finding check=cwe.input_validation.path_traversal
  res.send(data);
});
