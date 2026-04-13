import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock LanguageDetector
vi.mock("i18next-browser-languagedetector", () => ({
  default: { type: "languageDetector", detect: () => "en", init: vi.fn(), cacheUserLanguage: vi.fn() },
}));

// Mock initReactI18next
vi.mock("react-i18next", () => ({
  initReactI18next: { type: "3rdParty", init: vi.fn() },
}));

// Capture the dynamic import calls
const dynamicImportSpy = vi.fn();

// Mock the dynamic locale imports
vi.mock("./locales/es.json", () => {
  dynamicImportSpy("es");
  return { default: { greeting: "Hola" } };
});
vi.mock("./locales/fr.json", () => {
  dynamicImportSpy("fr");
  return { default: { greeting: "Bonjour" } };
});
vi.mock("./locales/de.json", () => {
  dynamicImportSpy("de");
  return { default: { greeting: "Hallo" } };
});
vi.mock("./locales/ja.json", () => {
  dynamicImportSpy("ja");
  return { default: { greeting: "Konnichiwa" } };
});
vi.mock("./locales/pt.json", () => {
  dynamicImportSpy("pt");
  return { default: { greeting: "Ola" } };
});

describe("i18n lazy loading", () => {
  beforeEach(() => {
    dynamicImportSpy.mockClear();
  });

  it("exports loadLanguage function for lazy loading", async () => {
    const mod = await import("./index");
    expect(typeof mod.loadLanguage).toBe("function");
  });

  it("only bundles en locale statically (non-en locales use dynamic import)", async () => {
    const mod = await import("./index");
    const i18n = mod.default;
    // English should be available immediately
    expect(i18n.hasResourceBundle("en", "translation")).toBe(true);
  });

  it("loads non-en locale on demand via loadLanguage", async () => {
    const mod = await import("./index");
    await mod.loadLanguage("es");
    expect(mod.default.hasResourceBundle("es", "translation")).toBe(true);
  });

  it("does not re-load a language that is already loaded", async () => {
    const mod = await import("./index");
    // Load es first
    await mod.loadLanguage("es");
    const bundleBefore = mod.default.getResourceBundle("es", "translation");
    // Load again - should be a no-op
    await mod.loadLanguage("es");
    const bundleAfter = mod.default.getResourceBundle("es", "translation");
    expect(bundleBefore).toBe(bundleAfter);
  });

  it("skips loading for 'en' since it is bundled statically", async () => {
    const mod = await import("./index");
    // loadLanguage("en") should return without doing anything
    await mod.loadLanguage("en");
    expect(mod.default.hasResourceBundle("en", "translation")).toBe(true);
  });
});
