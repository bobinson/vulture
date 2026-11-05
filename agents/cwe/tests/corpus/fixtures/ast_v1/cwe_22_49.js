// pins: the result of a request-family sink call is a network source (R-I) - a fetched document's path field reaches fs.readFile
export async function handler(req) {
  const answer = await fetch("https://cfg.example.test/doc.json");
  const cfg = await answer.json();
  return fs.promises.readFile(cfg.path);
}
