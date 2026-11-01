// pins: an aliased named import carries the imported symbol's words (R-H) - rf is readFile, so rf(req.query.f) is a sink
import { readFile as rf } from "fs";
export function handler(req) {
  rf(req.query.f, () => {});
}
