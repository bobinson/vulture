@Get(':id')
async findOne(@Req() req: Request, @Param('id') id: string) {
  if (req.query.mode === 'public') {
    return new UserPublicDto(await this.users.find(id));
  }
  if (!req.user) throw new UnauthorizedException();
  return new UserDto(await this.users.find(id));
}
