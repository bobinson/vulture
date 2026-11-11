import { existsSync } from "fs";
import type { Request, Response } from "express";

export class PresenceProbe {
  check(filePath: string): boolean {
    return existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
  }

  handle(req: Request, res: Response) {
    res.json({ ok: this.check(String(req.query.p)) });
  }
}
