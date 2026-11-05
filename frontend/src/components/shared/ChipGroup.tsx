import { memo, useCallback } from "react";
import { Chip, type ChipTone } from "./Chip.tsx";

// Feature 0074 — shared chip group: a legend followed by shared Chips
// (design: designs/0074-provenance-family.html, `.v-chipgroup`). With
// `onChange` it is a filter (one pressed button per item); without it, a
// read-only report (plain chips, no control). Content-sized (inline-flex), so
// it is the same box wherever it sits.

export interface ChipGroupItem {
  value: string;
  label: string;
  tone?: ChipTone;
  title?: string;
  /** data-testid override; defaults to `${group testId}-${value}`. */
  testId?: string;
}

interface ChipGroupProps {
  /** Shown as "<legend>:"; also the group's accessible name. */
  legend: string;
  items: ReadonlyArray<ChipGroupItem>;
  /** The active item (interactive mode). */
  value?: string;
  /** Present => interactive buttons; absent => read-only. */
  onChange?: (value: string) => void;
  /** Root data-testid. */
  testId: string;
}

interface ChipGroupEntryProps {
  item: ChipGroupItem;
  groupTestId: string;
  active: boolean;
  onChange?: (value: string) => void;
}

// One chip, memoised, with a handler stable across renders — no new closure
// per chip per render.
const ChipGroupEntry = memo(function ChipGroupEntry({ item, groupTestId, active, onChange }: ChipGroupEntryProps) {
  const { value } = item;
  const handleClick = useCallback(() => onChange?.(value), [onChange, value]);
  return (
    <Chip
      label={item.label}
      tone={item.tone}
      title={item.title}
      testId={item.testId ?? `${groupTestId}-${value}`}
      active={active}
      onClick={onChange ? handleClick : undefined}
    />
  );
});

function ChipGroupImpl({ legend, items, value, onChange, testId }: ChipGroupProps) {
  return (
    <div role="group" aria-label={legend} data-testid={testId} className="inline-flex items-center gap-2 align-middle">
      <span className="text-[11px] text-muted-light">{legend}:</span>
      <div className="flex gap-1">
        {items.map((item) => (
          <ChipGroupEntry
            key={item.value}
            item={item}
            groupTestId={testId}
            active={onChange !== undefined && item.value === value}
            onChange={onChange}
          />
        ))}
      </div>
    </div>
  );
}

export const ChipGroup = memo(ChipGroupImpl);
