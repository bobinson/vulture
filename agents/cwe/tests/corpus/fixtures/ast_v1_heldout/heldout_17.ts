// held-out heldout_17 (CWE-22): writeFileSync to a file-path parameter whose default is a resolved state path
// HELD-OUT-TOKENS: writeFileSync
import fs from "node:fs";

export function loadOrCreateKeys(filePath: string = defaultKeysPath()): StoredKeys {
  try {
    if (fs.existsSync(filePath)) {
      const parsed = readStored(filePath);
      if (parsed?.version === 1 && typeof parsed.keyId === "string") {
        const freshId = keyDigest(parsed.publicPem);
        if (freshId && freshId !== parsed.keyId) {
          const updated: StoredKeys = {
            ...parsed,
            keyId: freshId,
          };
          fs.writeFileSync(filePath, `${JSON.stringify(updated, null, 2)}\n`, { mode: 0o600 });
          return updated;
        }
        return parsed;
      }
    }
  } catch {
    // fall through and create fresh keys
  }
  return createKeys(filePath);
}
