// Feature 0101 tuning fixture: invented identifiers.
object Verify {
  def check(token: String): Boolean = {
    try {
      verifier.verify(token)
      true
    } catch { // EXPECT: finding check=cwe.insufficient_logging.cwe_778 the `catch {` opener of the arm block
      case e: JwtException => flagAttemptFailed(); false // EXPECT: finding
    }
  }
}

object VerifyMultiLine {
  def check(token: String): Boolean = {
    try {
      verifier.verify(token)
      true
    } catch { // EXPECT: finding check=cwe.insufficient_logging.cwe_778 the `catch {` opener of the arm block
      case e: JwtException => // EXPECT: finding
        flagAttemptFailed()
        false
    }
  }
}
