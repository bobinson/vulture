// Known false positive (arguably CWE-215): the routine returns early unless the
// build is a debug build, so release builds never reach the stack.
class Site {
  fun selfTest(): Result {
    if (!BuildConfig.DEBUG) return Result.error("disabled in release builds")
    try {
      return Result.ok(runChecks())
    } catch (e: Throwable) {
      return Result.error(message = e.stackTraceToString()) // EXPECT: finding known-gap debug-build-gate
    }
  }
}
