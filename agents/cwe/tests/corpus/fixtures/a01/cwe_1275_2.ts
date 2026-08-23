// SameSite explicitly relaxed to None: present AND vulnerable.
export function setSession (res: Response, sid: string): void {
  res.cookie('sid', sid, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
  })
}
