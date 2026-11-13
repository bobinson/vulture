// pins: 0104 WS-C - an exported probe helper a same-file caller hands a template path keeps that caller's flow (positive)
"use server";

import fs from "node:fs";

const UPLOAD_ROOT = "/srv/app/crates";

export function crateFound(filePath: string): boolean {
  return fs.existsSync(filePath);
}

export async function crateExists(fileName: string) {
  return crateFound(`${UPLOAD_ROOT}/${fileName}`);
}
