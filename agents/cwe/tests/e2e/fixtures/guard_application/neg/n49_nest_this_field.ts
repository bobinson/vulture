@Injectable()
export class InternalGuard implements CanActivate {
  constructor(private readonly cfg: ConfigService) {}
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest();
    if (req.headers['x-internal-token'] === this.token) {
      return true;
    }
    throw new UnauthorizedException();
  }
}
