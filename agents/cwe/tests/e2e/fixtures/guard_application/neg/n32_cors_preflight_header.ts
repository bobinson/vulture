import type { Request, Response, NextFunction } from "express";

export function auth(req: Request, res: Response, next: NextFunction) {
  // CORS preflights carry no credentials.
  if (req.method === 'OPTIONS' && req.headers['access-control-request-method']) {
    return next();
  }
  if (!req.user) return res.status(401).end();
  next();
}
