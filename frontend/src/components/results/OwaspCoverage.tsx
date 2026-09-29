import { useTranslation } from "react-i18next";
import { safeExternalUrl } from "@/lib/types.ts";
import type { OwaspCategoryCoverage, OwaspCoverageManifest } from "@/lib/types.ts";

interface CategoryLabelProps {
  category: OwaspCategoryCoverage;
  hit: boolean;
  selected: boolean;
  onSelect?: (id: string) => void;
}

/**
 * A category's name. With a handler it is a toggle that filters the findings
 * table to that category (feature 0096), and the OWASP source page moves to a
 * small link beside it; without one it is the source link, as in 0063.
 */
function CategoryLabel({ category: c, hit, selected, onSelect }: CategoryLabelProps) {
  const { t } = useTranslation();
  const tone = hit ? "text-foreground" : "text-muted-light";
  if (!onSelect) {
    return (
      <a
        href={c.source_url}
        target="_blank"
        rel="noreferrer"
        className={`truncate hover:text-accent ${tone}`}
        title={`${c.id} ${c.name}`}
      >
        {c.id} {c.name}
      </a>
    );
  }
  const href = safeExternalUrl(c.source_url);
  return (
    <>
      <button
        type="button"
        data-testid={`owasp-coverage-category-${c.id}`}
        aria-pressed={selected}
        onClick={() => onSelect(selected ? "all" : c.id)}
        title={t("results.owaspFilterByCategory", { id: c.id, name: c.name })}
        className={`truncate text-left rounded px-1 -mx-1 cursor-pointer transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${
          selected ? "bg-foreground text-surface" : `${tone} hover:text-accent hover:bg-cream-dark`
        }`}
      >
        {c.id} {c.name}
      </button>
      {href && (
        <a
          href={href}
          target="_blank"
          rel="noreferrer"
          aria-label={t("results.owaspSourceLink", { id: c.id })}
          title={t("results.owaspSourceLink", { id: c.id })}
          className="shrink-0 text-muted-light hover:text-accent"
        >
          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden>
            <path strokeLinecap="round" strokeLinejoin="round" d="M14 5h5v5m0-5L10 14M19 14v5H5V5h5" />
          </svg>
        </a>
      )}
    </>
  );
}

interface CategoryRowProps {
  category: OwaspCategoryCoverage;
  selected: boolean;
  onSelect?: (id: string) => void;
}

// A found category is a solid green dot, a checked-and-clean one a solid grey
// dot, and one the audit did not select only an outline.
function dotTone(hit: boolean, notSelected: boolean): string {
  if (hit) return "bg-success";
  return notSelected ? "border border-border" : "bg-border";
}

/**
 * One category of the card. A category the audit did not select (feature
 * 0096) says so instead of "0 / N", which would read as checked and clean,
 * and is never a filter: no finding carries its label.
 */
function CategoryRow({ category: c, selected, onSelect }: CategoryRowProps) {
  const { t } = useTranslation();
  const notSelected = c.selected === false;
  const hit = !notSelected && c.found_count > 0;
  return (
    <li className="flex items-center gap-2 min-w-0">
      <span
        aria-hidden
        className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotTone(hit, notSelected)}`}
      />
      <CategoryLabel category={c} hit={hit} selected={selected} onSelect={notSelected ? undefined : onSelect} />
      {notSelected ? (
        <span className="ml-auto shrink-0 italic text-muted-light">{t("results.owaspNotSelected")}</span>
      ) : (
        <span className={`ml-auto font-mono shrink-0 ${hit ? "text-success" : "text-muted-light"}`}>
          {c.found_count} / {c.mapped_count}
        </span>
      )}
    </li>
  );
}

interface OwaspCoverageProps {
  manifest: OwaspCoverageManifest;
  /** Feature 0096: categories the findings carry; only these filter. */
  selectableIds?: ReadonlySet<string>;
  /** The findings table's current OWASP category ("all" = none). */
  selectedCategory?: string;
  onSelectCategory?: (id: string) => void;
}

// Feature 0063: renders the OWASP Top 10 coverage manifest produced by the
// OWASP mapper agent. Every category is shown (never omitted); a non-completed
// CWE stage is flagged so a partial/failed/absent detection run is never
// mistaken for "all clear". Feature 0096: a category the findings are labelled
// with is also a toggle for the findings table's OWASP category filter.
export function OwaspCoverage({ manifest, selectableIds, selectedCategory = "all", onSelectCategory }: OwaspCoverageProps) {
  const { t } = useTranslation();
  const incomplete = manifest.cwe_stage_status !== "completed";
  // Feature 0096: a category the audit did not select was not checked, so it
  // is neither a hit nor part of what the audit covered.
  const covered = manifest.categories.filter((c) => c.selected !== false);
  const foundCount = covered.filter((c) => c.found_count > 0).length;

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
        <span className="text-muted-light">{foundCount}/{covered.length}</span>
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
        {manifest.categories.map((c) => (
          <CategoryRow
            key={c.id}
            category={c}
            selected={selectedCategory === c.id}
            onSelect={selectableIds?.has(c.id) ? onSelectCategory : undefined}
          />
        ))}
      </ul>
    </div>
  );
}
