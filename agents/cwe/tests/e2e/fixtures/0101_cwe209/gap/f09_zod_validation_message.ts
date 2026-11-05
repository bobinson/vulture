export function h(req, res) {
  const parsed = schema.safeParse(req.body)
  // EXPECT-NEXT: finding  known-gap zod validation message
  if (!parsed.success) return res.status(400).json({ error: parsed.error.message })
}
