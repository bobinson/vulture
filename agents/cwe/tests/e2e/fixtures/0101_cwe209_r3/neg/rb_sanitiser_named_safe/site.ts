import { Outcome } from "./outcome";

async function loadQ(id: string) {
  try {
    await db.get(id);
    return Outcome.ok();
  } catch (e) {
    logger.error(e);
    return new Outcome(false, "E_DB_UNAVAILABLE", e);
  }
}

async function loadSan(id: string) {
  try {
    await db.get(id);
    return { ok: true as const };
  } catch (e) {
    return { ok: false as const, error: toPublicMessage(e) };
  }
}

async function loadSafe(id: string) {
  try {
    await db.get(id);
    return { ok: true as const };
  } catch (e) {
    return { ok: false as const, error: sanitizeError(e) };
  }
}

async function loadClass(id: string) {
  try {
    await db.get(id);
    return { ok: true as const };
  } catch (e) {
    return { ok: false as const, error: e instanceof NotFoundError ? "not found" : "internal" };
  }
}

async function loadI18n(id: string) {
  try {
    await db.get(id);
    return { ok: true as const };
  } catch (e) {
    return { ok: false as const, error: t("errors.generic", { cause: e }) };
  }
}

export default async function handler(req: any, res: any) {
  const a = await loadQ("x");
  if (!a.ok) return res.status(500).json({ error: a.error }); // probe fp-Q-code-with-cause
  const b = await loadSan("x");
  if (!b.ok) return res.status(500).json({ error: b.error }); // probe fp-sanitiser
  const c = await loadSafe("x");
  if (!c.ok) return res.status(500).json({ error: c.error }); // EXPECT: clean fp-sanitiser2
  const d = await loadClass("x");
  if (!d.ok) return res.status(500).json({ error: d.error }); // probe clean-ternary-literals
  const f = await loadI18n("x");
  if (!f.ok) return res.status(500).json({ error: f.error }); // probe fp-i18n
}
