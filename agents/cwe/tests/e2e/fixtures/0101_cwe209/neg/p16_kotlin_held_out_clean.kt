suspend fun h(call: ApplicationCall) {
  try { run() } catch (e: IllegalStateException) {
    // EXPECT-NEXT: clean  kotlin held-out clean
    call.respondText("request failed")
  }
}
