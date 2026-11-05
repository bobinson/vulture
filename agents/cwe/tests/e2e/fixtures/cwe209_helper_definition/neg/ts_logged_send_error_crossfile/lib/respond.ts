export function sendJson(res: any, status: number, body: unknown) {
  res.status(status).json(body);
}

export function sendError(res: any, err: unknown) {
  logger.error(err);
  sendJson(res, 500, { error: "INTERNAL" });
}
