export async function fillReport(target: any, id: string) {
  try { target.rows = await store.read(id); } catch (err) { target.error = String(err); }
}
