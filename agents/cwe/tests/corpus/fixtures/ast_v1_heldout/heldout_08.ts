// held-out heldout_08 (CWE-22): a size-gated read of a file path handed in by a directory walk of a parameter directory
import fs from "node:fs/promises";

async function readCandidate(filePath: string, byteCap: number): Promise<string | null> {
  let st: Awaited<ReturnType<typeof fs.stat>> | null = null;
  try {
    st = await fs.stat(filePath);
  } catch (err) {
    if (errCodeIs(err, "ENOENT")) {
      return null;
    }
    throw err;
  }
  if (!st?.isFile() || st.size > byteCap) {
    return null;
  }
  try {
    return await fs.readFile(filePath, "utf-8");
  } catch (err) {
    if (errCodeIs(err, "ENOENT")) {
      return null;
    }
    throw err;
  }
}

export async function reviewFolder(dirPath: string, byteCap: number): Promise<string[]> {
  const files = await listWalkable(dirPath);
  const sources: string[] = [];
  for (const file of files) {
    const source = await readCandidate(file, byteCap);
    if (source !== null) {
      sources.push(source);
    }
  }
  return sources;
}
