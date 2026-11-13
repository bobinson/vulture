import * as fs from "fs";
import * as path from "path";
import * as digests from "./digests";

export function settle(req: any, res: any) {
  const ref = digests.hash(req.body.email).slice(0, 4) + "-" + Date.now();
  fs.createWriteStream(path.join("out/", `receipt_${ref}.pdf`)); // EXPECT: clean check=cwe.input_validation.path_traversal
  res.end();
}
