import { memo } from "react";
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

function ChipGroupImpl({ legend, items, value, onChange, testId }: ChipGroupProps) {
  return (
    <div role="group" aria-label={legend} data-testid={testId} className="inline-flex items-center gap-2 align-middle">
      <span className="text-[11px] text-muted-light">{legend}:</span>
      <div className="flex gap-1">
        {items.map((item) => (
          <Chip
            key={item.value}
            label={item.label}
            tone={item.tone}
            title={item.title}
            testId={item.testId ?? `${testId}-${item.value}`}
            active={onChange !== undefined && item.value === value}
            onClick={onChange && (() => onChange(item.value))}
          />
        ))}
      </div>
    </div>
  );
}

export const ChipGroup = memo(ChipGroupImpl);
