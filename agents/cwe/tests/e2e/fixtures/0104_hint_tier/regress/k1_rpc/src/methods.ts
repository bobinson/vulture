import { dropBenchFile } from "./files";

type Params = Record<string, unknown>;

export const methods = {
  "files.drop": async (params: Params) => {
    await dropBenchFile(String(params.target));
    return { ok: true };
  },
};
