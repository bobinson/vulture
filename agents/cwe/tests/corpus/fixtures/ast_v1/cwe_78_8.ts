// pins: strong command word matched by prefix, an imported callee whose one glued word begins with exec gets a request field (positive)
import { execa } from "execa";

export async function handler(req: any): Promise<void> {
  await execa(req.body.cmd);
}
