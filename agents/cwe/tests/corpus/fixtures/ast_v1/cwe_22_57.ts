// pins: a destructured params leaf of a parameter typed Request stays a request source in a handler factory - doc = params.doc passes only a forward-slash blocklist before res.sendFile(path.resolve(...)) (positive)
import path from "node:path";
import { type Request, type Response } from "express";

export function serveArchive() {
  return ({ params }: Request, res: Response) => {
    const doc = params.doc;
    if (!doc.includes("/")) {
      res.sendFile(path.resolve("archive/", doc));
    } else {
      res.status(403).end();
    }
  };
}
