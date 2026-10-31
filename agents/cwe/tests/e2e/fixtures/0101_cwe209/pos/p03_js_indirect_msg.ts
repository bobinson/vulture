try { f() } catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  // EXPECT-NEXT: finding  js indirect msg
  response.status(500).json({ error: message });
}
