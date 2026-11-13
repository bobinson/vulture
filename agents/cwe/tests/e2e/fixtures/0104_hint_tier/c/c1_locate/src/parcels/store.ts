import fs from "node:fs";
import path from "node:path";

const PARCEL_DIR = path.resolve(__dirname, "../../public/parcels");

/** The absolute path of a published parcel, or null when there is none. */
export function findParcel(fileName: string): string | null {
  const full = path.join(PARCEL_DIR, fileName);
  return fs.existsSync(full) ? full : null; // EXPECT: finding check=cwe.input_validation.path_traversal
}
