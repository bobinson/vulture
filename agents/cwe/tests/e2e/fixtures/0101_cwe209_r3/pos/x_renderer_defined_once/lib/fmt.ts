export function formatFailure(value: unknown): string {
  if (value instanceof Error) {
    return `${value.name}: ${value.message}`;
  }
  return String(value);
}
export function formatQuotaCode(err: unknown): string {
  if (err instanceof Error && err.message.includes("quota")) {
    return "QUOTA";
  }
  return "INTERNAL";
}
export function formatQuiet(err: unknown): string {
  logger.warn(`failed: ${String(err)}`);
  return "INTERNAL";
}
