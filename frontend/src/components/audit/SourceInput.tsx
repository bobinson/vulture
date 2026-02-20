import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import { FolderBrowser } from "./FolderBrowser.tsx";

interface SourceInputProps {
  sourceType: "git" | "local";
  onTypeChange: (t: "git" | "local") => void;
  value: string;
  onChange: (v: string) => void;
  error?: string | null;
}

export function SourceInput({ sourceType, onTypeChange, value, onChange, error }: SourceInputProps) {
  const { t } = useTranslation();
  const [browserOpen, setBrowserOpen] = useState(false);

  const handleBrowse = useCallback(() => {
    setBrowserOpen(true);
  }, []);

  const handleFolderSelect = useCallback(
    (path: string) => {
      onChange(path);
    },
    [onChange],
  );

  return (
    <div className="card p-5 space-y-4">
      <div>
        <p className="label">{t("audit.sourceCode")}</p>
        <p className="text-xs text-muted">{t("audit.sourceDesc")}</p>
      </div>

      {/* Type toggle */}
      <div className="flex gap-1 p-1 bg-cream rounded-lg w-fit">
        <button
          type="button"
          data-testid="source-type-git"
          className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-all duration-150 cursor-pointer ${
            sourceType === "git"
              ? "bg-surface text-foreground shadow-sm"
              : "text-muted hover:text-foreground"
          }`}
          onClick={() => onTypeChange("git")}
        >
          {t("audit.gitUrl")}
        </button>
        <button
          type="button"
          data-testid="source-type-local"
          className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-all duration-150 cursor-pointer ${
            sourceType === "local"
              ? "bg-surface text-foreground shadow-sm"
              : "text-muted hover:text-foreground"
          }`}
          onClick={() => onTypeChange("local")}
        >
          {t("audit.localPath")}
        </button>
      </div>

      {/* Input with browse button for local path */}
      <div className="flex gap-2">
        <input
          data-testid="source-url-input"
          type="text"
          className="input-field font-mono text-sm flex-1"
          placeholder={sourceType === "git" ? t("audit.gitPlaceholder") : t("audit.localPlaceholder")}
          value={value}
          onChange={(e) => onChange(e.target.value)}
        />
        {sourceType === "local" && (
          <button
            type="button"
            data-testid="browse-folder-btn"
            onClick={handleBrowse}
            className="btn-secondary px-3 py-2 text-xs shrink-0 flex items-center gap-1.5"
            title={t("browse.title")}
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M2 7.5V18a2 2 0 002 2h16a2 2 0 002-2V9a2 2 0 00-2-2h-6.5l-2-2.5H4a2 2 0 00-2 2z" />
            </svg>
            {t("browse.browseBtn")}
          </button>
        )}
      </div>

      {/* Helpful hint */}
      {sourceType === "local" && !value && (
        <p className="text-xs text-muted-light">{t("browse.hint")}</p>
      )}

      {/* Error */}
      {error && (
        <p className="text-xs text-danger font-medium" data-testid="source-error">
          {error}
        </p>
      )}

      {/* Folder Browser Dialog */}
      <FolderBrowser
        open={browserOpen}
        onClose={() => setBrowserOpen(false)}
        onSelect={handleFolderSelect}
        initialPath={value || "/home"}
      />
    </div>
  );
}
