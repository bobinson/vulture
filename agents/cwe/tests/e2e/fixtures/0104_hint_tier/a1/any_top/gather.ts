import fs from "node:fs";

export function gather(filePath) {
  return fs.readFileSync(filePath + basename(filePath) + allow(filePath) + validate(filePath) + shellEscape(filePath) + privateOnly(filePath) + allow(basename(filePath)) + validate(basename(filePath)) + shellEscape(basename(filePath)) + privateOnly(basename(filePath)) + validate(allow(filePath)) + shellEscape(allow(filePath)) + privateOnly(allow(filePath)) + shellEscape(validate(filePath)) + privateOnly(validate(filePath)) + privateOnly(shellEscape(filePath)) + validate(allow(basename(filePath)))); // EXPECT: finding check=cwe.input_validation.path_traversal HINT=none
}
