export async function loadLedger(id: string) {
  try {
    return { ok: true, value: await db.read(id) };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}
export async function loadCoded(id: string) {
  try {
    return { ok: true, value: await db.read(id) };
  } catch (err) {
    await db.audit.insert({ error: String(err) });
    return { ok: false, error: "LEDGER_UNAVAILABLE" };
  }
}
export async function loadDetail(id: string) {
  try {
    return { ok: true, value: await db.read(id) };
  } catch (err) {
    return { ok: false, message: String(err) };
  }
}
