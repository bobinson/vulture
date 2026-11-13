// pins: 0104 WS-C - a ternary of the argument and a join composes the probed path (positive)
"use server";

import fs from "node:fs";
import path from "node:path";

const ASSET_ROOT = "/srv/app/assets";

export async function assetExists(fileName: string) {
  const target = path.isAbsolute(fileName) ? fileName : path.join(ASSET_ROOT, fileName);
  return fs.existsSync(target);
}
