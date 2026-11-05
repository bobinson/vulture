// Feature 0101 held-out (LLD 4.6), CWE-778 Concept A at the idiom level.
// The failure completes a Promise, so the Future it backs carries it to the caller.
// Every identifier is invented.
// HELD-OUT-TOKENS: Promise, tryFailure

class MosaicService {
  def stitch(tiles: Seq[Tile], done: Promise[Mosaic]): Unit = {
    try {
      done.trySuccess(stitcher.stitch(tiles))
    } catch { // EXPECT: clean check=cwe.insufficient_logging.cwe_778
      case e: IOException => done.tryFailure(e) // EXPECT: finding check=cwe.insufficient_logging.scala_case_arm held-out-miss (concept: clean)
    }
  }

  def checkGrant(grant: String, done: Promise[Principal]): Unit = {
    try {
      done.trySuccess(grantVerifier.verifyToken(grant))
    } catch { // EXPECT: finding check=cwe.insufficient_logging.cwe_778
      case e: SecurityException => done.tryFailure(e) // EXPECT: finding check=cwe.insufficient_logging.scala_case_arm
    }
  }
}
