export function preview(url: string): void {
  const child = window.open(url, "_blank");
  child?.focus();
}
