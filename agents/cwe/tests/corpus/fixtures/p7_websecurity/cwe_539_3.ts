export function header(token: string): string {
  return "Set-Cookie: auth_token=" + token +
    "; Max-Age=31536000; HttpOnly; Secure; SameSite=Strict";
}
