import { existsSync } from "fs";

export default async function Page({ params: { filePath } }: { params: { filePath: string } }) {
  const ok = existsSync(filePath); // EXPECT: finding check=cwe.input_validation.path_traversal
  return <div>{ok ? "present" : "missing"}</div>;
}
