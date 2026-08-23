export function correlationLabel(prefix: string): string {
  const label = prefix + '-' + Math.random().toString(36).slice(2);
  return label;
}
