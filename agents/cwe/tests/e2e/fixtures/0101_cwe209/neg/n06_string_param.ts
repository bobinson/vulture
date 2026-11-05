function bad(res, status: number, error: string) {
  // EXPECT-NEXT: clean  string param
  return res.status(status).json({ error });
}
