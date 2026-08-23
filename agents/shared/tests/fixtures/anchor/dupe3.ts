// dupe3.ts -- 0076 fixture: one defect at line 15, three claims at 18/18/15.
// Two of the three carry a different title, so the residue is MEASURED by
// claim_probe's intra_file_duplicate label rather than deleted.
import { createHash } from "crypto";

export class TokenStore {
  private items = new Map<string, string>();

  put(key: string, value: string) {
    this.items.set(key, value);
  }

  sign(payload: string) {
    // the defect all three claims are about:
    return createHash("md5").update(payload).digest("hex");
  }

  clear() {
    this.items.clear();
  }
}
