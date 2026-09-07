object A {
  def a(p: String): Unit = {
    try { write(p) } catch {
      case NonFatal(e) =>
        ()
      case e: IOException =>
        logger.error("io", e)
      case e: RuntimeException =>
        throw e
    }
    val v = Try(write(p)).toOption
    val w = Try(write(p)).getOrElse(0)
  }
}
