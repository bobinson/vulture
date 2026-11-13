// pins: 0104 WS-C - a "use server" export statting a path joined from its argument: composed, so the probe still reports (positive)
"use server";

import { stat } from "node:fs/promises";
import path from "node:path";

const UPLOAD_ROOT = "/srv/app/crates";

export async function crateInfo(filePath: string) {
  const info = await stat(path.join(UPLOAD_ROOT, filePath));
  return { size: info.size, directory: info.isDirectory() };
}
