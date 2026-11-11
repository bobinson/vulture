// pins: 0104 WS-C - an exported function's bare hinted parameter, probed by statSync and never called in its file, is no request path (negative)
import fs from "node:fs";

// A utility wrapper: every caller builds the path it passes.
export function isFresh(filePath: string, maxAgeMs: number): boolean {
  const info = fs.statSync(filePath);
  return Date.now() - info.size < maxAgeMs;
}
