// pins: a container word among a parameter's inline type members names no request outside handler context - opts: { target; payload } in a helper, so opts.target reaching fs.writeFile is unknown(param) (negative)
import fs from "node:fs/promises";

export async function storeDraft(opts: { target: string; payload: string }): Promise<void> {
  await fs.writeFile(opts.target, opts.payload);
}
