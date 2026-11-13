// pins: 0104 WS-C - an awaited call composes the probed path (positive)
"use server";

import { promises as fsp } from "node:fs";
import path from "node:path";

const UPLOAD_ROOT = "/srv/app/crates";

export async function crateWeight(filePath: string) {
  const full = await fsp.realpath(path.join(UPLOAD_ROOT, filePath));
  const info = await fsp.stat(full);
  return info.size;
}
