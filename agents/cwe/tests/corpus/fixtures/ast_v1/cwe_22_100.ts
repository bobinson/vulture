// pins: 0104 WS-C - an exported locate helper probes a path it joins from its argument (positive)
import fs from "node:fs";
import path from "node:path";

const PARCEL_DIR = path.resolve(__dirname, "../../public/parcels");

export function findParcel(fileName: string): string | null {
  const full = path.join(PARCEL_DIR, fileName);
  return fs.existsSync(full) ? full : null;
}
