// pins: a template-literal command interpolating a request query field is arg 0 of an imported exec-prefixed synchronous sink (positive)
import { execSync } from "child_process";

export function handler(req: any): void {
  execSync(`git clone ${req.query.url}`);
}
