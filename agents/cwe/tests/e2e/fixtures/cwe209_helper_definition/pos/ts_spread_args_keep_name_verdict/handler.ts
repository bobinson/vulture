import { sendError } from "./lib/respond";

export async function show(req: any, res: any) {
  try {
    res.json(await store.read(req.params.id));
  } catch (err: any) {
    sendError(res, ...[500, err.message]); // EXPECT: finding
  }
}
