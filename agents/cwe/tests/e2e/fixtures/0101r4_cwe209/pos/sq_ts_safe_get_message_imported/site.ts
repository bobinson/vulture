import { safeGetMessage } from "./util";

export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (err) {
    res.status(500).json({ error: safeGetMessage(err) }); // EXPECT: finding tp-ts-null-safe-getter
  }
}
