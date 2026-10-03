import { memo, useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import type { ChipTone } from "./Chip.tsx";
import { ChipGroup, type ChipGroupItem } from "./ChipGroup.tsx";

// Feature 0074 — read-only anchor result in the finding detail (design:
// designs/0074-provenance-family.html S4). Two independent facts side by side:
// what 0076's quote verifier found (validation.checks[id=anchor].result) and
// where the model's claimed line fell (extras.claimed_line_range), plus the
// claimed line and, when the verifier moved it, the anchored line. Absent
// pieces are omitted, never invented; no anchor check renders nothing.

type Json = Record<string, unknown>;

const STATUS_TONES: Readonly<Record<string, ChipTone>> = {
  exact: "success",
  reanchored: "info",
  ambiguous: "warning",
  near_miss: "warning",
  found_elsewhere: "warning",
  absent: "danger",
};

const RANGE_TONES: Readonly<Record<string, ChipTone>> = {
  in_file: "neutral",
  past_eof: "warning",
  no_line: "neutral",
};

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null;
}

function isAnchorCheck(check: unknown): check is Json & { result: string } {
  return isObject(check) && check.id === "anchor" && typeof check.result === "string";
}

function findAnchorCheck(validation: unknown): (Json & { result: string }) | undefined {
  const checks = isObject(validation) ? validation.checks : undefined;
  return Array.isArray(checks) ? checks.find(isAnchorCheck) : undefined;
}

function ownTone(tones: Readonly<Record<string, ChipTone>>, key: unknown): ChipTone | undefined {
  return typeof key === "string" && Object.hasOwn(tones, key) ? tones[key] : undefined;
}

function rangeItem(range: unknown, t: TFunction): ChipGroupItem | undefined {
  const tone = ownTone(RANGE_TONES, range);
  if (!tone) return undefined;
  return { value: "range", label: t(`results.anchor.range.${range as string}`), tone, testId: "anchor-range" };
}

function lineLabel(claimed: number, delta: unknown): string {
  const moved = typeof delta === "number" && Number.isFinite(delta) && delta !== 0;
  return moved ? `L${claimed} → L${claimed + delta}` : `L${claimed}`;
}

function lineItem(extras: Json): ChipGroupItem | undefined {
  const claimed = extras.claimed_line;
  if (typeof claimed !== "number" || !Number.isFinite(claimed)) return undefined;
  return { value: "line", label: lineLabel(claimed, extras.delta), tone: "neutral", testId: "anchor-line" };
}

function anchorItems(check: Json & { result: string }, t: TFunction): ChipGroupItem[] {
  const extras = isObject(check.extras) ? check.extras : {};
  const status: ChipGroupItem = {
    value: "status",
    label: t(`results.anchor.status.${check.result}`, { defaultValue: check.result }),
    tone: ownTone(STATUS_TONES, check.result) ?? "neutral",
    testId: "anchor-status",
  };
  return [status, rangeItem(extras.claimed_line_range, t), lineItem(extras)].filter(
    (item): item is ChipGroupItem => item !== undefined,
  );
}

interface AnchorResultProps {
  validation?: Record<string, unknown>;
}

function AnchorResultImpl({ validation }: AnchorResultProps) {
  const { t } = useTranslation();
  const items = useMemo(() => {
    const check = findAnchorCheck(validation);
    return check ? anchorItems(check, t) : undefined;
  }, [validation, t]);
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
