export function concatText(req: any, done: (s: string) => void) {
  // EXPECT-NEXT: finding one-line data callback with string concatenation
  let b = ""; req.on("data", (c: string) => b += c);
  req.on("end", () => done(b));
}
