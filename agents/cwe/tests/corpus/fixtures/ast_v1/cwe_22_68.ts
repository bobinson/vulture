// pins: the same inline-typed container parameter in handler context stays a request source - a response parameter beside it makes saveDraft a handler, so opts.target reaching fs.writeFile reports (positive)
import fs from "node:fs";
import { type Response } from "express";

export function saveDraft(opts: { target: string; payload: string }, res: Response): void {
  fs.appendFile(opts.target, opts.payload, () => {
    res.end();
  });
}
