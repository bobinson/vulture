import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { api } from "@/lib/api.ts";
import type { DirEntry } from "@/lib/types.ts";

interface FolderBrowserProps {
  open: boolean;
  onClose: () => void;
  onSelect: (path: string) => void;
  initialPath?: string;
}

export function FolderBrowser({ open, onClose, onSelect, initialPath }: FolderBrowserProps) {
  const { t } = useTranslation();
  const [currentPath, setCurrentPath] = useState(initialPath || "/");
  const [entries, setEntries] = useState<DirEntry[]>([]);
  const [parentPath, setParentPath] = useState("/");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);

  const browse = useCallback(async (path: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.browseFilesystem(path);
      setCurrentPath(res.path);
      setParentPath(res.parent);
      setEntries(res.entries);
    } catch {
      setError(t("browse.loadError"));
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (open) {
      browse(initialPath || "/");
      dialogRef.current?.showModal();
    } else {
      dialogRef.current?.close();
    }
  }, [open, browse, initialPath]);

  const handleSelect = useCallback(() => {
    onSelect(currentPath);
    onClose();
  }, [currentPath, onSelect, onClose]);

  const handleBackdropClick = useCallback(
    (e: React.MouseEvent<HTMLDialogElement>) => {
      if (e.target === dialogRef.current) onClose();
    },
    [onClose],
  );

  const breadcrumbs = currentPath.split("/").filter(Boolean);

  if (!open) return null;

  return (
    <dialog
      ref={dialogRef}
      className="fixed inset-0 z-50 bg-transparent p-0 m-auto w-full max-w-xl backdrop:bg-black/40"
      onClick={handleBackdropClick}
      onCancel={onClose}
    >
      <div className="bg-surface rounded-xl shadow-xl border border-border flex flex-col max-h-[80vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-border">
          <h3 className="text-sm font-semibold text-foreground">{t("browse.title")}</h3>
          <button
            type="button"
            onClick={onClose}
            className="w-7 h-7 flex items-center justify-center rounded-md text-muted hover:text-foreground hover:bg-cream-dark transition-colors cursor-pointer"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Breadcrumb path */}
        <div className="px-5 py-2.5 border-b border-border bg-cream/50">
          <div className="flex items-center gap-1 text-xs font-mono overflow-x-auto">
            <button
              type="button"
              onClick={() => browse("/")}
              className="text-accent hover:text-accent/80 shrink-0 cursor-pointer"
            >
              /
            </button>
            {breadcrumbs.map((segment, i) => {
              const fullPath = "/" + breadcrumbs.slice(0, i + 1).join("/");
              const isLast = i === breadcrumbs.length - 1;
              return (
                <span key={fullPath} className="flex items-center gap-1">
                  <span className="text-muted-light">/</span>
                  {isLast ? (
                    <span className="text-foreground font-medium">{segment}</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => browse(fullPath)}
                      className="text-accent hover:text-accent/80 cursor-pointer"
                    >
                      {segment}
                    </button>
                  )}
                </span>
              );
            })}
          </div>
        </div>

        {/* Current selection */}
        <div className="px-5 py-2 border-b border-border bg-accent/5">
          <p className="text-xs text-muted">
            {t("browse.selected")}: <span className="font-mono font-medium text-foreground">{currentPath}</span>
          </p>
        </div>

        {/* Directory listing */}
        <div className="flex-1 overflow-y-auto min-h-0" style={{ maxHeight: "360px" }}>
          {loading ? (
            <div className="flex items-center justify-center py-12">
              <div className="w-5 h-5 border-2 border-accent/30 border-t-accent rounded-full animate-spin" />
            </div>
          ) : error ? (
            <div className="px-5 py-8 text-center">
              <p className="text-xs text-danger">{error}</p>
              <button
                type="button"
                onClick={() => browse(currentPath)}
                className="mt-2 text-xs text-accent hover:underline cursor-pointer"
              >
                {t("common.retry")}
              </button>
            </div>
          ) : (
            <div className="py-1">
              {/* Go up */}
              {currentPath !== "/" && (
                <button
                  type="button"
                  onClick={() => browse(parentPath)}
                  className="w-full flex items-center gap-3 px-5 py-2 text-left hover:bg-cream-dark transition-colors cursor-pointer"
                >
                  <svg className="w-4 h-4 text-muted shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" transform="rotate(180, 12, 12)" />
                  </svg>
                  <span className="text-sm text-muted">..</span>
                </button>
              )}

              {entries.length === 0 && !loading && (
                <p className="px-5 py-6 text-xs text-muted text-center">{t("browse.empty")}</p>
              )}

              {entries.map((entry) => (
                <button
                  key={entry.path}
                  type="button"
                  onClick={() => {
                    if (entry.is_dir) {
                      browse(entry.path);
                    }
                  }}
                  className={`w-full flex items-center gap-3 px-5 py-2 text-left transition-colors ${
                    entry.is_dir
                      ? "hover:bg-cream-dark cursor-pointer"
                      : "opacity-40 cursor-default"
                  }`}
                  disabled={!entry.is_dir}
                >
                  {entry.is_dir ? (
                    <svg className="w-4 h-4 text-accent shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M2 7.5V18a2 2 0 002 2h16a2 2 0 002-2V9a2 2 0 00-2-2h-6.5l-2-2.5H4a2 2 0 00-2 2z" />
                    </svg>
                  ) : (
                    <svg className="w-4 h-4 text-muted shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                    </svg>
                  )}
                  <span className={`text-sm truncate ${entry.is_dir ? "text-foreground font-medium" : "text-muted"}`}>
                    {entry.name}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer with actions */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-border">
          <button
            type="button"
            onClick={onClose}
            className="btn-secondary px-4 py-1.5 text-xs"
          >
            {t("common.cancel")}
          </button>
          <button
            type="button"
            onClick={handleSelect}
            className="btn-primary px-5 py-1.5 text-xs"
          >
            {t("browse.selectFolder")}
          </button>
        </div>
      </div>
    </dialog>
  );
}
