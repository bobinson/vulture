import { sendError } from "./lib/respond";

export async function show(req: any, res: any) {
  try {
    res.json(await store.read(req.params.id));
  } catch (err) {
    sendError(res, err); // probe clean-reported-once-at-the-helper
  }
}
