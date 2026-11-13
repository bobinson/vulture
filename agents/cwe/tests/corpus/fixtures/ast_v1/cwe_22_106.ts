// pins: 0104 WS-C - a member of a call (new URL(...).pathname) composes the probed path (positive)
"use server";

import fs from "node:fs";

const UPLOAD_BASE = new URL("file:///srv/app/crates/");

export async function crateInfo(fileName: string) {
  return fs.statSync(new URL(fileName, UPLOAD_BASE).pathname);
}
