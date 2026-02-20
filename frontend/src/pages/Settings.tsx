import { useState } from "react";
import { useTranslation } from "react-i18next";

const MODELS = [
  { value: "gpt-4o", label: "GPT-4o" },
  { value: "claude-sonnet", label: "Claude Sonnet" },
  { value: "gemini-pro", label: "Gemini Pro" },
];

const LANGUAGES = [
  { value: "en", label: "English" },
  { value: "es", label: "Español" },
  { value: "fr", label: "Français" },
  { value: "de", label: "Deutsch" },
  { value: "ja", label: "日本語" },
  { value: "pt", label: "Português" },
];

const STORAGE_KEY = "vulture_settings";

interface StoredSettings {
  model: string;
  apiKey: string;
}

function loadSettings(): StoredSettings {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as StoredSettings;
  } catch { /* ignore corrupted data */ }
  return { model: "gpt-4o", apiKey: "" };
}

function saveSettings(settings: StoredSettings): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(settings));
}

export function Settings() {
  const { t, i18n } = useTranslation();
  const [model, setModel] = useState(() => loadSettings().model);
  const [apiKey, setApiKey] = useState(() => loadSettings().apiKey);
  const [saved, setSaved] = useState(false);

  const handleSave = () => {
    saveSettings({ model, apiKey });
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleLanguageChange = (lang: string) => {
    i18n.changeLanguage(lang);
  };

  return (
    <div className="max-w-lg space-y-6">
      {/* Language */}
      <div className="card p-5 space-y-4">
        <div>
          <p className="label">{t("settings.language")}</p>
          <p className="text-[12px] text-muted">{t("settings.languageDesc")}</p>
        </div>
        <div className="flex gap-2">
          {LANGUAGES.map((lang) => (
            <button
              key={lang.value}
              type="button"
              className={`px-4 py-2 text-[13px] rounded-lg border transition-colors cursor-pointer ${
                i18n.language === lang.value
                  ? "border-accent bg-accent/5 text-accent font-medium"
                  : "border-border text-muted hover:border-border-dark"
              }`}
              onClick={() => handleLanguageChange(lang.value)}
            >
              {lang.label}
            </button>
          ))}
        </div>
      </div>

      {/* Model config */}
      <div className="card p-5 space-y-4">
        <div>
          <p className="label">{t("settings.modelConfig")}</p>
          <p className="text-[12px] text-muted">{t("settings.modelConfigDesc")}</p>
        </div>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <label className="text-[12px] font-medium text-muted block">
              {t("settings.llmModel")}
            </label>
            <select
              className="input-field cursor-pointer"
              value={model}
              onChange={(e) => setModel(e.target.value)}
            >
              {MODELS.map((m) => (
                <option key={m.value} value={m.value}>
                  {m.label}
                </option>
              ))}
            </select>
          </div>
          <div className="space-y-1.5">
            <label className="text-[12px] font-medium text-muted block">
              {t("settings.apiKey")}
            </label>
            <input
              type="password"
              className="input-field font-mono"
              placeholder={t("settings.apiKeyPlaceholder")}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button type="button" className="btn-primary" onClick={handleSave}>
            {t("settings.save")}
          </button>
          {saved && (
            <span className="text-[13px] text-success font-medium">
              <svg className="w-4 h-4 inline mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              {t("settings.saved")}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
