import { schema } from "./schema";
export default async function handler(req: any, res: any) {
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ message: "invalid", details: parsed.error }); // probe fp-Y-zod-singular
  const auth = await signIn("credentials", { redirect: false });
  if (auth?.error) return res.status(401).json({ message: auth.error }); // EXPECT: clean fp-Y-nextauth-code
  const job = await queue.getJob(req.query.id);
  return res.json({ state: job.state, reason: job.failedReason, message: job.error }); // probe ?-Y-crossfile
}
