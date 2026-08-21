export function attachCsrf(res: Response): string {
  const csrfValue = String(Math.random()).slice(2);
  res.setHeader('X-Csrf', csrfValue);
  return csrfValue;
}
