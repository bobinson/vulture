import { describe, expect, it } from "vitest";

// Feature 0102: the browser session is an HttpOnly cookie that scripts never
// see. This guard keeps it that way: no production source may keep a
// credential in Web Storage or a script-readable cookie, or build an
// Authorization header. Removing the legacy key (the one-time purge) is the
// only storage operation on a credential key that is allowed.

const SOURCES = import.meta.glob<string>("/src/**/*.{ts,tsx}", {
  query: "?raw",
  import: "default",
  eager: true,
});

// Test sources the glob does see (it never lists the importing file itself).
const TEST_WITNESSES = ["/src/lib/api.test.ts", "/src/test/setup.ts"];
const TEST_SOURCE = /\.test\.tsx?$|\/__tests__\/|^\/src\/test\//;

const LEGACY_KEY = "vulture_token";
const CREDENTIAL_KEY = /token|jwt|session/i;
// Whole comment lines are blanked (line numbers kept); code is never skipped.
const COMMENT_LINE = /^[ \t]*(?:\/\/|\/\*|\*).*$/gm;

function codeOf(src: string): string {
  return src.replace(COMMENT_LINE, "");
}

// Production sources with comment lines blanked once, up front.
const PRODUCTION = Object.entries(SOURCES)
  .filter(([file]) => !TEST_SOURCE.test(file))
  .map(([file, src]) => [file, codeOf(src)] as const);

const STORAGE = String.raw`\b(?:localStorage|sessionStorage)\s*`;
const NOT_METHOD = String.raw`(?!(?:setItem|getItem|removeItem|clear|key|length)\b)`;
// Each pattern captures the key expression: setItem(key, …), [key] = …, .key = …
const WRITES = [
  new RegExp(String.raw`${STORAGE}\.\s*setItem\s*\(\s*([^,)]+?)\s*,`, "g"),
  new RegExp(String.raw`${STORAGE}\[\s*([^\]]+?)\s*\]\s*=(?!=)`, "g"),
  new RegExp(String.raw`${STORAGE}\.\s*${NOT_METHOD}([A-Za-z_$][\w$]*)\s*=(?!=)`, "g"),
];
// getItem(key), [key] and .key when not assigned.
const READS = [
  new RegExp(String.raw`${STORAGE}\.\s*getItem\s*\(\s*([^)]+?)\s*\)`, "g"),
  new RegExp(String.raw`${STORAGE}\[\s*([^\]]+?)\s*\](?!\s*=(?!=))`, "g"),
  new RegExp(String.raw`${STORAGE}\.\s*${NOT_METHOD}([A-Za-z_$][\w$]*)\b(?!\s*=(?!=))`, "g"),
];
const AUTH_HEADER = [
  /\bauthorization["'`]?\s*:/gi, // { Authorization: … } or { "authorization": … }
  /["'`]authorization["'`]\s*[,\]]/gi, // .set("Authorization", …), h["Authorization"]
  /["'`]Bearer\s/gi, // a "Bearer <token>" value
];

interface Hit {
  line: number;
  text: string;
}

// Detectors take code whose comment lines are already blanked (codeOf).
function hits(code: string, pattern: RegExp, keep: (m: RegExpExecArray) => boolean = () => true): Hit[] {
  return [...code.matchAll(pattern)]
    .filter(keep)
    .map((m) => ({ line: code.slice(0, m.index).split("\n").length, text: m[0].trim() }));
}

function declaredString(name: string, src: string): string | undefined {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
  const decl = new RegExp(String.raw`\b(?:const|let|var)\s+${name.replace(/\$/g, "\\$")}\s*(?::[^=]+)?=\s*(["'\`])(.*?)\1`);
  return decl.exec(src)?.[2];
}

// The names a key expression stands for: a literal's value, or an identifier
// together with the string it is declared as in the same file.
function keyNames(expr: string, src: string): string[] {
  const literal = /^(["'`])(.*)\1$/s.exec(expr);
  if (literal) return [literal[2]];
  const value = declaredString(expr, src);
  return value === undefined ? [expr] : [expr, value];
}

function keyHits(src: string, patterns: RegExp[], matches: (name: string) => boolean): Hit[] {
  return patterns.flatMap((p) => hits(src, p, (m) => keyNames(m[1], src).some(matches)));
}

const isLegacyKey = (name: string) => name === LEGACY_KEY;
const isCredentialKey = (name: string) => CREDENTIAL_KEY.test(name);

const DETECTORS = {
  writesLegacyKey: (src: string) => keyHits(src, WRITES, isLegacyKey),
  storesCredential: (src: string) => keyHits(src, WRITES, isCredentialKey),
  readsCredential: (src: string) => keyHits(src, READS, isCredentialKey),
  buildsAuthorization: (src: string) => AUTH_HEADER.flatMap((p) => hits(src, p)),
  touchesDocumentCookie: (src: string) => hits(src, /\bdocument\s*\.\s*cookie\b/g),
};
type DetectorName = keyof typeof DETECTORS;

function flaggedBy(src: string): DetectorName[] {
  const code = codeOf(src);
  return (Object.keys(DETECTORS) as DetectorName[]).filter((name) => DETECTORS[name](code).length > 0);
}

function violations(name: DetectorName): string[] {
  return PRODUCTION.flatMap(([file, code]) => DETECTORS[name](code).map((h) => `${file}:${h.line}: ${h.text}`));
}

const FIXTURES: [string, string, DetectorName[]][] = [
  [
    "the legacy key written through a constant",
    'const TOKEN_KEY = "vulture_token";\nlocalStorage.setItem(TOKEN_KEY, t);',
    ["writesLegacyKey", "storesCredential"],
  ],
  ["the legacy key written as a property", "localStorage.vulture_token = t;", ["writesLegacyKey", "storesCredential"]],
  ["a jwt put into sessionStorage by index", 'sessionStorage["jwt"] = t;', ["storesCredential"]],
  ["a credential read back", 'const raw = localStorage.getItem("vulture_token");', ["readsCredential"]],
  ["a bearer header object", "fetch(u, { headers: { Authorization: `Bearer ${t}` } });", ["buildsAuthorization"]],
  ["a header set by name", 'headers.set("authorization", value);', ["buildsAuthorization"]],
  ["a script-readable cookie", 'document.cookie = "session=" + t;', ["touchesDocumentCookie"]],
  ["the one-time purge", 'try { localStorage.removeItem("vulture_token"); } catch { /* blocked */ }', []],
  [
    "a UI preference",
    'const COLLAPSE_KEY = "vulture_sidebar_pinned";\nlocalStorage.setItem(COLLAPSE_KEY, "true");\nlocalStorage.getItem(COLLAPSE_KEY);',
    [],
  ],
  ["a commented-out write", '// localStorage.setItem("vulture_token", t);', []],
];

describe("credential storage guard (0102)", () => {
  it("reads the production sources and leaves the tests out", () => {
    const files = PRODUCTION.map(([file]) => file);
    expect(files).toEqual(expect.arrayContaining(["/src/lib/api.ts", "/src/lib/auth.tsx", "/src/components/layout/Sidebar.tsx"]));
    expect(Object.keys(SOURCES)).toEqual(expect.arrayContaining(TEST_WITNESSES));
    expect(files.filter((file) => TEST_WITNESSES.includes(file))).toEqual([]);
  });

  it.each(FIXTURES)("detectors: %s", (_name, src, expected) => {
    expect(flaggedBy(src)).toEqual(expected);
  });

  it("no production source writes vulture_token", () => {
    expect(violations("writesLegacyKey")).toEqual([]);
  });

  it("no production source puts a token, jwt or session key into Web Storage", () => {
    expect(violations("storesCredential")).toEqual([]);
  });

  it("no production source reads a token, jwt or session key from Web Storage", () => {
    expect(violations("readsCredential")).toEqual([]);
  });

  it("no production source builds an Authorization header", () => {
    expect(violations("buildsAuthorization")).toEqual([]);
  });

  it("no production source touches document.cookie", () => {
    expect(violations("touchesDocumentCookie")).toEqual([]);
  });
});
