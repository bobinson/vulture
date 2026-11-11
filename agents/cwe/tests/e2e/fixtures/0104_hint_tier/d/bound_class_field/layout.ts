import * as fs from "fs";
import * as path from "path";
import type { Request, Response } from "express";

const ROOT = "/srv/shards";

export class Shards {
  hash = (name: string) => name.slice(0, 2) + "/" + name;

  get(req: Request, res: Response) {
    res.send(fs.readFileSync(path.join(ROOT, this.hash(String(req.query.name))))); // EXPECT: finding check=cwe.input_validation.path_traversal
  }
}
