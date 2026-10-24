// Feature 0101, CWE-778 Concept B: a keyword that NAMES an outcome (a catalog key,
// an enum member, a constant, a case label, a pattern branch) is not an
// authorization decision. One that DECIDES or ANSWERS one is. Invented identifiers.
export const CATALOG = [
  ...ERRORS.UNAUTHORIZED, // EXPECT: clean check=cwe.insufficient_logging.auth_decision
];
export const CODES = {
  UNAUTHORIZED: { code: 401 }, // EXPECT: clean check=cwe.insufficient_logging.auth_decision
};
export const AUTH_DENIED = 'x'; // EXPECT: clean check=cwe.insufficient_logging.auth_decision
export function describeCode(c: string) {
  switch (c) {
    case Codes.AUTH_DENIED: // EXPECT: clean check=cwe.insufficient_logging.auth_decision
      return 'denied text';
  }
  return '';
}
export const REASON_RE = /invalid|unauthorized|forbidden/i; // EXPECT: clean check=cwe.insufficient_logging.auth_decision
export const UNAUTHORIZED = 401; // EXPECT: clean check=cwe.insufficient_logging.auth_decision
export class Status {
  static readonly FORBIDDEN = 403; // EXPECT: clean check=cwe.insufficient_logging.auth_decision
}
export interface Flags {
  forbidden?: boolean; // EXPECT: clean check=cwe.insufficient_logging.auth_decision
}
export type DeniedCode = typeof Codes.UNAUTHORIZED; // EXPECT: clean check=cwe.insufficient_logging.auth_decision
export enum Reason {
  Unauthorized = 401, // EXPECT: clean check=cwe.insufficient_logging.auth_decision
  Other = 500,
}

// ---- decisions and answers: reported ----
export function answerDenied(res: Res) {
  res.status(Catalog.UNAUTHORIZED.code).json({ // EXPECT: finding check=cwe.insufficient_logging.auth_decision
    ok: false,
  });
}
export function answerPayload(res: Res) {
  res.json({
    ...buildErrorPayload(Catalog.UNAUTHORIZED), // EXPECT: finding check=cwe.insufficient_logging.auth_decision
  });
}
export function answerCode(res: Res) {
  sendError(res, 401, Codes.AUTH_DENIED); // EXPECT: finding check=cwe.insufficient_logging.auth_decision
}
export function gateRole(role: Role) {
  switch (role) {
    case Role.Guest: return FORBIDDEN; // EXPECT: finding check=cwe.insufficient_logging.auth_decision
    default: return allow();
  }
}
export function verdictFor(session: Session) {
  return {
    unauthorized: !session || session.expired, // EXPECT: finding check=cwe.insufficient_logging.auth_decision
  };
}

export function gateBoth(expired: boolean, forbidden: boolean) { // EXPECT: finding check=cwe.insufficient_logging.auth_decision known-gap: a parameter on the declaration line
  if (expired||forbidden) { return deny(); } // EXPECT: finding check=cwe.insufficient_logging.auth_decision
  return allow();
}

// ---- known gaps, pinned to the observed verdict ----
export function looksDenied(x: string) {
  return /forbidden/i.test(x); // EXPECT: finding check=cwe.insufficient_logging.auth_decision known-gap: a regex test over a keyword is read as a decision
}

// A multi-line throw: the keyword sits on an argument line, so it is a decision.
export function refuse(id: string) {
  throw new HttpError(
    Codes.FORBIDDEN, // EXPECT: finding check=cwe.insufficient_logging.auth_decision
    id,
  );
}
