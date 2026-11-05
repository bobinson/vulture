export async function readSignupJob(id: string) {
  try {
    return { state: 'done', value: await jobs.read(id) };
  } catch (err) {
    return { state: 'failed', error: err.message };
  }
}
export async function readInviteState(id: string) {
  const row = await invites.find(id);
  if (!row) return { ok: false, error: 'INVITE_NOT_FOUND' };
  return { ok: true, row };
}
