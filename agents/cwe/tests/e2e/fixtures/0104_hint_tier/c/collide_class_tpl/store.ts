import fs from "node:fs";

const ATLAS_ROOT = "/srv/atlas";

export class AtlasShelf {
  has(filePath: string): boolean {
    return fs.existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
  }

  hasAtlas(fileName: string): boolean {
    return this.has(ATLAS_ROOT + "/" + fileName);
  }
}
