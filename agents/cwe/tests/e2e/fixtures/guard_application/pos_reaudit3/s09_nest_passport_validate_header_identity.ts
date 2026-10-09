@Injectable()
export class JwtStrategy {
  validate(req: Request) {
    const sub = req.headers['x-jwt-sub'];
    if (sub) {
      return new UserEntity({ id: sub });
    }
    throw new UnauthorizedException();
  }
}
