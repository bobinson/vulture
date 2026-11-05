async function runJob(id: string) {
  try {
    await work(id);
    return { ok: true, error: null };
  } catch (e) {
    await db.jobs.update({ where: { id }, data: { status: "FAILED", error: (e as Error).message } });
    return { ok: false, error: "JOB_FAILED" };
  }
}

export default async function handler(req: any, res: any) {
  const r = await runJob(req.body.id);
  if (!r.ok) return res.status(500).json({ error: r.error }); // EXPECT: clean clean-persisted-raw-returned-code
}
