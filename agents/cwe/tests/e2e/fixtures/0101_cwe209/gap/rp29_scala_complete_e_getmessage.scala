object Routes {
  def get() = try { run() } catch {
    // EXPECT-NEXT: clean  known-gap scala complete e getMessage
    case e: Exception => complete(StatusCodes.InternalServerError, e.getMessage)
  }
}
