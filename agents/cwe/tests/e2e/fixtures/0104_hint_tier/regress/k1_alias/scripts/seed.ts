import { readOwnFile } from "../src/lib/files";

export function seed(): void {
  console.log(readOwnFile("welcome.txt").length);
}
