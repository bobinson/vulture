// Clean twin of cwe_1275_2: SameSite=Lax, on a later line of a multi-line call.
export function setSession (res: Response, sid: string): void {
  res.cookie('sid', sid, {
    httpOnly: true,
    secure: true,
    path: '/',
    domain: 'example.com',
    sameSite: 'lax',
  })
}
