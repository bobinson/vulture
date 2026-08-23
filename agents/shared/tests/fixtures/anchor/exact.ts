// exact.ts -- 0076 fixture: the model's quote matches at the cited line.
export function loadConfig(path: string) {
  const raw = readFileSync(path, "utf8");
  return JSON.parse(raw);
}
