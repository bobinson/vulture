class Speech {
  fun load() {
    try {
      readSettings()
    } catch (_: Throwable) {
      useDefaults()
    }
  }

  fun upload(req: SpeechRequest) {
    val conn = openUpload(req)
    val payload = buildRequestBody(req)
    // EXPECT-NEXT: clean  outbound request body binding never resolves a placeholder
    conn.outputStream.use { it.write(payload.toByteArray()) }
  }
}
