static void Main() {
  try { Run(); } catch (Exception ex) {
    // EXPECT-NEXT: clean  cs console error
    Console.Error.WriteLine(ex.Message);
  }
}
