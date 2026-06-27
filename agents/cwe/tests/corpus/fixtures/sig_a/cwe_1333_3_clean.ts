// Safe: bounded digit quantifier, no nested repetition.
const phoneRe = /^\d{7,15}-end$/;

export function isPhone(value: string): boolean {
  return phoneRe.test(value);
}
