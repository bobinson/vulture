import fs from "node:fs";
import path from "node:path";

const ATLAS_ROOT = "/srv/atlas";

export class AtlasShelf {
  has(filePath: string): boolean {
    return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
  }

  hasAtlas(fileName: string): boolean {
    return this.has(path.join(ATLAS_ROOT, fileName));
  }
}
