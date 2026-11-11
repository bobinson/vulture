import express from "express";
import { statSync } from "fs";

export class SheetMeta {
  static describe(filePath: string) {
    const st = statSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
    return { size: st.size, blocks: st.blocks };
  }
}

export const router = express.Router();

router.get("/meta", (req, res) => {
  res.json(SheetMeta.describe(String(req.query.p)));
});
