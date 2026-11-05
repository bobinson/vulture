export async function create(req: any, res: any) {
  const result = await submit(req.body);
  if (!result.ok) return res.status(400).json({ error: "INVALID", details: result.errors }); // EXPECT: clean clean-Y-plural
}
