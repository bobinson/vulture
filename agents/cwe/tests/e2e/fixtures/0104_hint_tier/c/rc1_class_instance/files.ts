import express from "express";
import * as fs from "fs";

export class PresenceProbe {
  exists(filePath: string): boolean {
    return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
  }
}

const probe = new PresenceProbe();
export const app = express();

app.get("/api/exists", (req, res) => {
  res.json({ exists: probe.exists(req.query.p as string) });
});
