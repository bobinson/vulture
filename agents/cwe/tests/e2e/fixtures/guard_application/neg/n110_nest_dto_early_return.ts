@Post('users')
async create(@Req() req: Request, @Body() body: CreateUserDto) {
  if (req.query.dryRun === 'true') {
    return new UserPreview(body);
  }
  if (!req.user) throw new UnauthorizedException();
  return new UserDto(await this.users.create(body));
}
