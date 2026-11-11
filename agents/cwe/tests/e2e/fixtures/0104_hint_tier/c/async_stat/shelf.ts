import fsp from "node:fs/promises";

export async function onShelf(filePath?: string | null): Promise<boolean> {
  if (!filePath) {
    return false;
  }
  try {
    await fsp.stat(filePath); // EXPECT: clean check=cwe.input_validation.path_traversal
    return true;
  } catch {
    return false;
  }
}
