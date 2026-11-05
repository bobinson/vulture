export function sendError(res: any, status: number, detail: string) {
  res.status(status).json({ error: detail });
}
