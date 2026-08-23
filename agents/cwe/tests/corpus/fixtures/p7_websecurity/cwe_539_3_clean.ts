export function header(token: string): string {
  return "Set-Cookie: auth_token=" + token +
    "; Max-Age=1800; HttpOnly; Secure; SameSite=Strict";
}
