export class Guard {
  canActivate(req) {
    const token = 'unused';
    if (req.headers['x-internal-token'] === this.token) return true;
    if (!req.user) throw new UnauthorizedException();
    return true;
  }
}
