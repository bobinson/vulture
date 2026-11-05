// held-out heldout_05 (CWE-78): RegExp.exec over a date string after a typeof/emptiness check, reached from a params object
const splitDay = (
  raw: unknown,
): { year: number; month: number; day: number } | undefined => {
  if (typeof raw !== "string" || !raw.trim()) {
    return undefined;
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(raw.trim());
  if (!match) {
    return undefined;
  }
  const [, y, m, d] = match;
  return { year: Number(y), month: Number(m) - 1, day: Number(d) };
};

const dayToMs = (raw: unknown): number | undefined => {
  const parts = splitDay(raw);
  if (!parts) {
    return undefined;
  }
  return Date.UTC(parts.year, parts.month, parts.day);
};

export const rangeOf = (params: { startDate?: unknown; endDate?: unknown }) => {
  const startMs = dayToMs(params.startDate);
  const endMs = dayToMs(params.endDate);
  return { startMs, endMs };
};
