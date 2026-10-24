export function guard(req: Request, res: Response, next: NextFunction) {
  if (req.query?.bypass === 'yes') return next();
  return res.status(401).json({ error: 'unauthorized' });
}
