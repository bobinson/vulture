// nearmiss.ts -- 0076 fixture: the model retyped line 7 from memory and
// dropped the encoding argument. That is a mislocated MEMORY, not a
// fabrication: near_miss (Jaccard 0.8), and never a demotion.
import { readFileSync } from "fs";

export function loadTemplate(p: string) {
  const t = readFileSync(p, "utf8");
  return t.trim();
}
