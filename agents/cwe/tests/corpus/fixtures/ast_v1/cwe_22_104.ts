// pins: 0104 WS-C - a template literal composes the probed path (positive)
"use server";

import fs from "node:fs";

const ASSET_ROOT = "/srv/app/assets";

export async function assetExists(fileName: string) {
  return fs.existsSync(`${ASSET_ROOT}/${fileName}`);
}
