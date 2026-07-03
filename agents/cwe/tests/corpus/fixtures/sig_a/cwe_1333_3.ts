// CWE-1333: nested unbounded quantifier in a RegExp literal — ReDoS.
const phoneRe = /^(\d+)*-end$/;

export function isPhone(value: string): boolean {
  return phoneRe.test(value);
}
