// Feature 0101, CWE-778 residual (R778-7): a BARE case label naming an auth
// outcome is skipped by Concept B (LLD 5.1.3), so an unlogged auth-failure arm
// whose body carries no auth keyword is not reported. A known recall trade: the
// skip is what keeps `case Codes.AUTH_DENIED:` in a message catalog clean.

export function routeByStatus(status: Status, res: Res) {
  switch (status) {
    case AuthStatus.UNAUTHORIZED: // EXPECT: clean residual: R778-7 bare label, arm body not judged
      res.redirect('/signin');
      break;
  }
}
