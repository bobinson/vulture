// Feature 0101, CWE-778 Concept B: a declaration whose VALUE is a boolean
// expression is the authorization decision itself, not an outcome's name. Each
// decision is reported; an outcome name bound to a plain value stays clean.

export function gateAdmin(user: User, res: Res) {
  const forbidden = !user.isAdmin; // EXPECT: finding
  if (check(user)) {
    res.send(1);
  }
  return res;
}

export function gateOwner(user: User, res: Res) {
  const forbidden = user.role !== 'admin' && !user.owner; // EXPECT: finding
  if (allowed(user)) {
    res.send(1);
  }
  return res;
}

export function gateExpiry(user: User, res: Res) {
  let unauthorized = user.token == null || user.expired; // EXPECT: finding
  if (fresh(user)) {
    res.send(1);
  }
  return res;
}

export function gateLevel(user: User, res: Res) {
  const forbidden = user.level < 3; // EXPECT: finding
  if (ok(user)) {
    res.send(1);
  }
  return res;
}

export const FORBIDDEN = 403; // EXPECT: clean
