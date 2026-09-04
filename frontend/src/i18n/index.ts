import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import en from "./locales/en.json";

const resources: Record<string, { translation: Record<string, unknown> }> = {
  en: { translation: en },
};

// Every locale EXCEPT en. The template-literal form `import(`./locales/${lng}.json`)`
// makes en.json a candidate of the dynamic import too, and a module that is BOTH
// statically and dynamically imported cannot be split into its own chunk — the
// bundler keeps it in the main one and warns INEFFECTIVE_DYNAMIC_IMPORT. en is
// deliberately static: it is the default and the fallback, so it must be present
// before the first render. Excluding it here is what lets the other five split.
const localeLoaders = import.meta.glob<{ default: Record<string, unknown> }>([
  "./locales/*.json",
  "!./locales/en.json",
]);

export async function loadLanguage(lng: string): Promise<void> {
  if (resources[lng]) return;
  const load = localeLoaders[`./locales/${lng}.json`];
  // An unrecognised language is not an error: i18next falls back to en. The
  // previous form threw here and every caller swallowed it.
  if (!load) return;
  const mod = await load();
  resources[lng] = { translation: mod.default };
  i18n.addResourceBundle(lng, "translation", mod.default, true, true);
}

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    fallbackLng: "en",
    interpolation: {
      escapeValue: false,
    },
    detection: {
      order: ["localStorage", "navigator"],
      caches: ["localStorage"],
    },
  });

// Load detected language on init (best-effort; en fallback handles failures)
const detected = i18n.language?.split("-")[0];
if (detected && detected !== "en") void loadLanguage(detected).catch(() => {});

i18n.on("languageChanged", (lng: string) => {
  const base = lng.split("-")[0];
  if (base !== "en") void loadLanguage(base).catch(() => {});
});

export default i18n;
