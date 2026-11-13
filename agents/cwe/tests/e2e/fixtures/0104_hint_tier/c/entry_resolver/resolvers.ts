import { existsSync } from "fs";

export const resolvers = {
  Query: {
    sheetExists: (_parent: unknown, { filePath }: { filePath: string }) => existsSync(filePath), // EXPECT: finding check=cwe.input_validation.path_traversal
  },
};
