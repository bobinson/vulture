import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { api } from "@/lib/api.ts";
import type { MaskedSpan, MaskedValues } from "@/lib/types.ts";

// Feature 0074 (verification item 1b) — verify a masked value in place.
//
// A finding's snippet keeps its masked text everywhere. When it masks
// something, a "Show unmasked" switch asks the backend to re-read the scanned
// file and put each value back into its row. Values are never stored here
// beyond this component's state: not in a shared cache, not in the URL, not in
// a log. Switching off, or closing the detail (unmount), drops them. Copy
// buttons elsewhere keep copying the masked text.

const PLACEHOLDER = /(\*\*\*REDACTED\*\*\*|\[redacted\])/;
const ROW_NUMBER = /^(\d+): /;

type RevealState =
  | { kind: "off" }
  | { kind: "loading" }
  | { kind: "done"; result: MaskedValues }
  | { kind: "error" };

function hasPlaceholder(snippet: string): boolean {
  return PLACEHOLDER.test(snippet);
}

function valuesByRow(spans: MaskedSpan[]): Map<number, Map<number, string>> {
  const rows = new Map<number, Map<number, string>>();
  for (const span of spans) {
    if (!span.value) continue;
    const row = rows.get(span.line) ?? new Map<number, string>();
    row.set(span.ordinal, span.value);
    rows.set(span.line, row);
  }
  return rows;
}

function revealRow(row: string, values: Map<number, string> | undefined, rowIndex: number): ReactNode {
  if (!values) return row;
  let ordinal = 0;
  return row.split(PLACEHOLDER).map((part, i) => {
    if (i % 2 === 0) return <Fragment key={`${rowIndex}-${i}`}>{part}</Fragment>;
    const value = values.get(ordinal++);
    if (value === undefined) return <Fragment key={`${rowIndex}-${i}`}>{part}</Fragment>;
    return (
      <mark key={`${rowIndex}-${i}`} className="bg-warning/30 text-terminal-text rounded px-0.5" data-testid="revealed-value">
        {value}
      </mark>
    );
  });
}

function revealedSnippet(snippet: string, result: MaskedValues): ReactNode {
  const byRow = valuesByRow(result.spans);
  return snippet.split("\n").map((row, i) => {
    const line = Number(ROW_NUMBER.exec(row)?.[1] ?? 0);
    return (
      <Fragment key={i}>
        {i > 0 && "\n"}
        {revealRow(row, byRow.get(line), i)}
      </Fragment>
    );
  });
}

const REASON_KEYS: Record<string, string> = {
  changed_since_scan: "results.reveal.changed",
  source_unavailable: "results.reveal.unavailable",
  ambiguous: "results.reveal.ambiguous",
};

function revealMessage(state: RevealState, t: TFunction): string | null {
  if (state.kind === "loading") return t("results.reveal.loading");
  if (state.kind === "error") return t("results.reveal.error");
  if (state.kind !== "done" || state.result.values_included) return null;
  const reason = state.result.reason ?? "";
  if (!reason) return t("results.reveal.notPermitted");
  return t(REASON_KEYS[reason] ?? "results.reveal.unverifiable");
}

interface MaskedSnippetProps {
  auditId: string;
  findingId: string;
  snippet: string;
}

export function MaskedSnippet({ auditId, findingId, snippet }: MaskedSnippetProps) {
  const { t } = useTranslation();
  const [state, setState] = useState<RevealState>({ kind: "off" });
  // Bumped on every switch, so a slow response for an earlier switch-on can
  // never land after the switch was turned off or the detail closed.
  const generation = useRef(0);
  useEffect(() => () => { generation.current++; }, []);

  const masked = hasPlaceholder(snippet);
  const on = state.kind !== "off";

  const onToggle = () => {
    const mine = ++generation.current;
    if (on) {
      setState({ kind: "off" });
      return;
    }
    setState({ kind: "loading" });
    api.maskedValues(auditId, findingId).then(
      (result) => { if (generation.current === mine) setState({ kind: "done", result }); },
      () => { if (generation.current === mine) setState({ kind: "error" }); },
    );
  };

  const message = revealMessage(state, t);
  const body = state.kind === "done" && state.result.values_included
    ? revealedSnippet(snippet, state.result)
    : snippet;

  return (
    <div className="space-y-1.5">
      {masked && (
        <div className="flex items-center gap-2 text-[11px]">
          <button
            type="button"
            role="switch"
            aria-checked={on}
            onClick={onToggle}
            className={`relative inline-flex h-4 w-7 shrink-0 rounded-full transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent ${on ? "bg-accent" : "bg-border"}`}
          >
            <span className={`inline-block h-3 w-3 mt-0.5 rounded-full bg-surface transition-transform ${on ? "translate-x-3.5" : "translate-x-0.5"}`} />
            <span className="sr-only">{t("results.reveal.toggle")}</span>
          </button>
          <span className="text-foreground">{t("results.reveal.toggle")}</span>
          <span className="text-muted-light">{t("results.reveal.hint")}</span>
        </div>
      )}
      <pre className="text-[12px] font-mono bg-terminal text-terminal-text rounded-lg px-4 py-3 overflow-x-auto">
        {body}
      </pre>
      {message && <p role="status" className="text-[11px] text-muted">{message}</p>}
    </div>
  );
}
