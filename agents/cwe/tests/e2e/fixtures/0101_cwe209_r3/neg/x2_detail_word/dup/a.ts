export async function loadTwice(id: string) { try { return { ok: true }; } catch (e) { return { ok: false, error: String(e) }; } }
