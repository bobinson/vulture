// Feature 0074 (T1) — the ONE whitespace set every runtime trims provenance,
// origin and override strings with: Go's unicode.IsSpace (what
// strings.TrimSpace strips). String.prototype.trim() is not it: it strips
// U+FEFF and keeps U+0085, so a tier Go calls LLM-family could read as a
// different family here. U+FEFF and U+001C-U+001F are not whitespace anywhere.

export const GO_SPACE: ReadonlySet<string> = new Set(
  "\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000",
);

/** Trim Go's unicode.IsSpace set from both ends (every member is one UTF-16 unit). */
export function trimGoSpace(value: string): string {
  let start = 0;
  let end = value.length;
  while (start < end && GO_SPACE.has(value[start])) start++;
  while (end > start && GO_SPACE.has(value[end - 1])) end--;
  return value.slice(start, end);
}
