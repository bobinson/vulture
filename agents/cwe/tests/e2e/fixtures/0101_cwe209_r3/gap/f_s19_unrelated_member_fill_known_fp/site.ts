export function trackUpload(upload) {
  upload.promise.catch((err) => { upload.error = err.message; });
}
export async function verify(req, res) {
  const applied = await applyProof(req.body);
  if (!applied.ok) return res.status(400).json({ error: applied.error }); // EXPECT: finding clean-crossfile-codes
}
