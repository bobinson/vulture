import { z } from "zod";
import { existsSync } from "node:fs";
import { publicProcedure, router } from "./rpc";

export const fileRouter = router({
  exists: publicProcedure
    .input(z.object({ filePath: z.string() }))
    .query(({ input: { filePath } }) => existsSync(filePath)), // EXPECT: finding check=cwe.input_validation.path_traversal
});
