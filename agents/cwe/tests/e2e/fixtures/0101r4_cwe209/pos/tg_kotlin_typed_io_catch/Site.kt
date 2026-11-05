class Site {
  fun handle(call: ApplicationCall) {
    try {
      store.load()
    } catch (e: IOException) {
      call.respondText(e.message ?: "x") // EXPECT: finding tp-kotlin-typed-io
    }
  }
}
