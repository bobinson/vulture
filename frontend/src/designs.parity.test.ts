import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The design system lives in `frontend/designs/` and is the single source of
 * truth for tokens. The running app still declares its Tailwind `@theme` in
 * `src/index.css`, so the two can drift — a token changed in one place and
 * not the other is exactly the "design and implementation disagree" failure
 * the shared system exists to prevent. This test pins them to each other.
 *
 * Contract:
 *   - every `--color-*` / `--font-*` in `@theme` exists in `designs/tokens.css`
 *     with the same value, and vice versa;
 *   - the severity palette (`severity-*` utilities) is expressed as tokens in
 *     `designs/tokens.css` and the utility values match them;
 *   - `designs/components.css` uses tokens, not hex literals.
 */

const FRONTEND = resolve(__dirname, "..");
const read = (rel: string) => readFileSync(resolve(FRONTEND, rel), "utf8");

function customProps(block: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const m of block.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;]+);/gi)) {
    out.set(m[1], m[2].trim().replace(/\s+/g, " "));
  }
  return out;
}

function themeBlock(css: string): string {
  const m = css.match(/@theme\s*\{([\s\S]*?)\n\}/);
  if (!m) throw new Error("src/index.css has no @theme block");
  return m[1];
}

function rootBlock(css: string): string {
  const m = css.match(/:root\s*\{([\s\S]*?)\n\}/);
  if (!m) throw new Error("designs/tokens.css has no :root block");
  return m[1];
}

describe("design system parity: designs/tokens.css ↔ src/index.css", () => {
  const app = read("src/index.css");
  const tokens = read("designs/tokens.css");
  const appTheme = customProps(themeBlock(app));
  const designTokens = customProps(rootBlock(tokens));

  it("every @theme token exists in designs/tokens.css with the same value", () => {
    const drift: string[] = [];
    for (const [name, value] of appTheme) {
      const got = designTokens.get(name);
      if (got === undefined) drift.push(`${name}: missing from designs/tokens.css`);
      else if (got !== value) drift.push(`${name}: app=${value} design=${got}`);
    }
    expect(drift, drift.join("\n")).toEqual([]);
  });

  it("every colour/font token in designs/tokens.css exists in @theme", () => {
    // The design system may ADD tokens the app has not adopted yet (spacing,
    // radius, severity) — but a colour or font token it defines must be one
    // the app can actually use, or the mockups are drawn in colours the
    // product cannot render.
    const orphans = [...designTokens.keys()].filter(
      (n) => /^--(color|font)-/.test(n) && !/^--color-severity-/.test(n) && !appTheme.has(n),
    );
    expect(orphans, orphans.join("\n")).toEqual([]);
  });

  it("severity utilities in the app match the severity tokens", () => {
    const drift: string[] = [];
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
      const util = app.match(
        new RegExp(`@utility severity-${sev}\\s*\\{\\s*background-color:\\s*(#[0-9A-Fa-f]{6});\\s*color:\\s*(#[0-9A-Fa-f]{6});`),
      );
      if (!util) {
        drift.push(`severity-${sev}: utility not found in src/index.css`);
        continue;
      }
      const bg = designTokens.get(`--color-severity-${sev}-bg`);
      const fg = designTokens.get(`--color-severity-${sev}`);
      if (bg?.toUpperCase() !== util[1].toUpperCase()) drift.push(`severity-${sev} bg: app=${util[1]} design=${bg}`);
      if (fg?.toUpperCase() !== util[2].toUpperCase()) drift.push(`severity-${sev} fg: app=${util[2]} design=${fg}`);
    }
    expect(drift, drift.join("\n")).toEqual([]);
  });

  it("designs/components.css draws only with tokens — no hex literals", () => {
    const components = read("designs/components.css");
    const stripped = components.replace(/\/\*[\s\S]*?\*\//g, "");
    const hexes = [...stripped.matchAll(/#[0-9A-Fa-f]{3,8}\b/g)].map((m) => m[0]);
    expect(hexes, `hex literals in components.css: ${hexes.join(", ")}`).toEqual([]);
  });
});
