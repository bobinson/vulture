import type { Request, Response, NextFunction } from "express";

const ALLOWED = new Set(["10.0.0.5", "127.0.0.1"]);

export function adminOnly(req: Request, res: Response, next: NextFunction) {
  const ip = req.socket.remoteAddress ?? "";
  if (ALLOWED.has(ip)) return next();
  if (!req.session?.isStaff) return res.status(403).send("forbidden");
  return next();
}
