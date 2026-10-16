import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import type { ChipTone } from "./Chip.tsx";
import { ChipGroup, type ChipGroupItem } from "./ChipGroup.tsx";
import { ANCHOR_CHECK_ID, ANCHOR_RANGE_TONES, ANCHOR_STATUS_TONES } from "@/lib/anchor.ts";

// Feature 0074 — read-only anchor result in the finding detail (design:
// designs/0074-provenance-family.html S4). Two independent facts side by side:
// what 0076's quote verifier found (validation.checks[id=anchor].result) and
// where the model's claimed line fell (extras.claimed_line_range), plus the
// claimed line and, when the persisted line_start differs from it, the line
// the row now sits on. A stamped delta alone is not a move: with REANCHOR=false
// or VERIFY=observe the agent records the delta and leaves the line where the
// model put it. Absent pieces are omitted, never invented; no anchor check
// renders nothing.

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null;
}

function isAnchorCheck(check: unknown): check is Json & { result: string } {
  return isObject(check) && check.id === ANCHOR_CHECK_ID && typeof check.result === "string";
}

function findAnchorCheck(validation: unknown): (Json & { result: string }) | undefined {
  const checks = isObject(validation) ? validation.checks : undefined;
  // Last wins when a blob carries several anchor checks: the rule every reader
  // (anchor_extras, the window stage) uses.
  return Array.isArray(checks) ? checks.findLast(isAnchorCheck) : undefined;
}

function ownTone(tones: Readonly<Record<string, ChipTone>>, key: unknown): ChipTone | undefined {
  return typeof key === "string" && Object.hasOwn(tones, key) ? tones[key] : undefined;
}

function rangeItem(range: unknown, t: TFunction): ChipGroupItem | undefined {
  const tone = ownTone(ANCHOR_RANGE_TONES, range);
  if (!tone) return undefined;
  return { value: "range", label: t(`results.anchor.range.${range as string}`), tone, testId: "anchor-range" };
}

function isLine(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function lineLabel(claimed: number, lineStart: number | undefined): string {
  const moved = isLine(lineStart) && lineStart !== claimed;
  return moved ? `L${claimed} → L${lineStart}` : `L${claimed}`;
}

function lineItem(extras: Json, lineStart: number | undefined): ChipGroupItem | undefined {
  const claimed = extras.claimed_line;
  if (!isLine(claimed)) return undefined;
  return { value: "line", label: lineLabel(claimed, lineStart), tone: "neutral", testId: "anchor-line" };
}

function anchorItems(check: Json & { result: string }, lineStart: number | undefined, t: TFunction): ChipGroupItem[] {
  const extras = isObject(check.extras) ? check.extras : {};
  const status: ChipGroupItem = {
    value: "status",
    label: t(`results.anchor.status.${check.result}`, { defaultValue: check.result }),
    tone: ownTone(ANCHOR_STATUS_TONES, check.result) ?? "neutral",
    testId: "anchor-status",
  };
  return [status, rangeItem(extras.claimed_line_range, t), lineItem(extras, lineStart)].filter(
    (item): item is ChipGroupItem => item !== undefined,
  );
}

interface AnchorResultProps {
  validation?: Record<string, unknown>;
  /** The row's persisted line_start: the arrow shows only when it differs from claimed_line. */
  lineStart?: number;
}

function AnchorResultImpl({ validation, lineStart }: AnchorResultProps) {
  const { t } = useTranslation();
  const items = useMemo(() => {
    const check = findAnchorCheck(validation);
    return check ? anchorItems(check, lineStart, t) : undefined;
  }, [validation, lineStart, t]);
  if (!items) return null;
  // A block of its own, so it stacks with the detail's other rows while the
  // group itself stays content-sized.
  return (
    <div className="flex">
      <ChipGroup legend={t("results.anchor.title")} items={items} testId="anchor-result" />
    </div>
  );
}

export const AnchorResult = memo(AnchorResultImpl);
