export async function create(req: any, res: any) {
  const result = await submit(req.body);
  if (!result.ok) return res.status(400).json({ error: "INVALID", message: result.errorCode }); // EXPECT: clean clean-Y-code-string
}
