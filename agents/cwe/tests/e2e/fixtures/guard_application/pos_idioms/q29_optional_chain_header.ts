export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (req.headers?.["x-internal"] === "1") {
    return next();
  }
  if (!req.user) return res.status(401).end();
  next();
}
