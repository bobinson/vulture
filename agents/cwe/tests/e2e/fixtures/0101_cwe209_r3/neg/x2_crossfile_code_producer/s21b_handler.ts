import { readSignupJob, readInviteState } from './s21a_lib_producer';
export async function signupStatus(req, res) {
  const job = await readSignupJob(req.body.id);
  res.json({ state: job.state, error: job.error }); // probe tp-crossfile
}
export async function invitationStatus(req, res) {
  const invite = await readInviteState(req.body.id);
  if (!invite.ok) return res.status(404).json({ error: invite.error }); // EXPECT: clean clean-crossfile
}
