/**
 * A scan whose codebase could not be attributed to a project is keyed
 * `unresolved:<mount>` (a bare container mount with no project segment) and is
 * deliberately never folded into a real target.
 */
export function isUnattributed(targetKey: string): boolean {
  return targetKey.startsWith("unresolved:");
}

/**
 * A readable name for a target key when the server has not supplied one — the
 * report page is reachable by deep link, with no target list loaded behind it.
 *
 * Keys are `<kind>:<identity>`; the last non-empty path segment of the
 * identity is the project name for both forms the backend produces (a
 * normalised git remote and a canonical filesystem path).
 */
export function deriveTargetName(targetKey: string): string {
  const identity = targetKey.replace(/^[a-z0-9_-]+:/i, "");
  const segments = identity.split("/").filter(Boolean);
  return segments[segments.length - 1] ?? targetKey;
}

/**
 * A timestamp that came off the Go wire, or null when there is nothing real
 * to show.
 *
 * Go marshals a zero `time.Time` as `0001-01-01T00:00:00Z` — a NON-empty
 * string that parses to a perfectly valid Date, so `if (!value)` and
 * `Number.isNaN(...)` both wave it through. Rendered naively it becomes
 * "1/1/1" or "Jan 1", which reads as a date a scan actually ran on. Any
 * `time.Time` field without a pointer or `omitempty` can arrive this way, so
 * every wire date is parsed HERE rather than at each call site — the guard
 * previously existed on the codebase list alone, and the aggregate table's
 * "last seen" column rendered "Jan 1" for the same input.
 */
export function parseWireDate(value?: string): Date | null {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.getFullYear() < 1970 ? null : date;
}

/**
 * A scan's timestamp, as short as it can be while still telling two scans of
 * the same day apart.
 *
 * A scan is identified to a reader by WHEN it ran, not by the first eight
 * characters of its id — the picker and the history rail both led with the
 * hex, which no one can rank. Unparseable input is returned as-is rather than
 * swallowed: a wrong-looking date is debuggable, a blank chip is not.
 */
export function formatScanStamp(value: string): string {
  const when = parseWireDate(value);
  if (when === null) return value;
  return when.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

/**
 * A target key without its scheme prefix — `path:/srv/app` reads as `/srv/app`
 * and `git:github.com/o/r` as `github.com/o/r`. The prefix is how the backend
 * partitions keys; it is not something a reader has to know about.
 */
export function targetKeyLabel(targetKey: string): string {
  return targetKey.replace(/^[a-z0-9_-]+:/i, "");
}
