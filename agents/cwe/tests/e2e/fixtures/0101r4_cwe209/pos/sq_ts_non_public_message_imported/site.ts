import { getNonPublicMessage } from "./util";
export async function show(req: any, res: any) {
  try {
    await store.read(req.params.id);
  } catch (e) {
    res.status(500).json({ error: getNonPublicMessage(e) }); // EXPECT: finding tp-ts-negated-qualifier
  }
}
