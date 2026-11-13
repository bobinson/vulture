import fs from "fs";

export default function Viewer({ exists }) {
  return exists ? "present" : "missing";
}

export async function getServerSideProps({ params: { filePath } }) {
  return { props: { exists: fs.existsSync(filePath) } }; // EXPECT: finding check=cwe.input_validation.path_traversal
}
