import { useTranslation } from "react-i18next";
import type { OwaspCoverageManifest } from "@/lib/types.ts";

// Feature 0063: renders the OWASP Top 10 coverage manifest produced by the
// OWASP mapper agent. Every category is shown (never omitted); a non-completed
// CWE stage is flagged so a partial/failed/absent detection run is never
// mistaken for "all clear".
export function OwaspCoverage({ manifest }: { manifest: OwaspCoverageManifest }) {
  const { t } = useTranslation();
  const incomplete = manifest.cwe_stage_status !== "completed";
  const foundCount = manifest.categories.filter((c) => c.found_count > 0).length;

  return (
    <div
      data-testid="owasp-coverage"
      className="card px-4 py-3 text-[12px] border-l-2 border-accent"
    >
      <div className="flex items-center gap-2 flex-wrap mb-2">
        <svg
          className="w-4 h-4 text-accent shrink-0"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
          />
        </svg>
        <span className="font-semibold text-foreground">{t("results.owaspCoverage")}</span>
        <span className="font-mono text-[11px] px-1.5 py-0.5 rounded bg-cream text-muted border border-border">
          {manifest.edition}
        </span>
        <span className="text-muted-light">{foundCount}/{manifest.categories.length}</span>
        {incomplete && (
          <span
            role="alert"
            className="text-[11px] font-medium px-2 py-0.5 rounded bg-[#FEF3C7] text-[#92400E]"
          >
            {t("results.owaspCweStageWarning")} {manifest.cwe_stage_status}
          </span>
        )}
      </div>

      <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
        {manifest.categories.map((c) => {
          const hit = c.found_count > 0;
          return (
            <li key={c.id} className="flex items-center gap-2 min-w-0">
              <span
                aria-hidden
                className={`w-1.5 h-1.5 rounded-full shrink-0 ${hit ? "bg-success" : "bg-border"}`}
              />
              <a
                href={c.source_url}
                target="_blank"
                rel="noreferrer"
                className={`truncate hover:text-accent ${hit ? "text-foreground" : "text-muted-light"}`}
                title={`${c.id} ${c.name}`}
              >
                {c.id} {c.name}
              </a>
              <span className={`ml-auto font-mono shrink-0 ${hit ? "text-success" : "text-muted-light"}`}>
                {c.found_count} / {c.mapped_count}
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
