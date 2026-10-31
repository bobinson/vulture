object Gen {
  def build(xs: Seq[Int]): JsonArray = {
    val arr = new JsonArray()
    for (v <- xs) {
      // EXPECT-NEXT: clean N13 (held-out)
      arr.add(v)
    }
    arr
  }
}
