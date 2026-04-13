import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import LanguageDetector from "i18next-browser-languagedetector";

import en from "./locales/en.json";

const resources: Record<string, { translation: Record<string, unknown> }> = {
  en: { translation: en },
};

export async function loadLanguage(lng: string): Promise<void> {
  if (resources[lng]) return;
  const mod = await import(`./locales/${lng}.json`);
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
