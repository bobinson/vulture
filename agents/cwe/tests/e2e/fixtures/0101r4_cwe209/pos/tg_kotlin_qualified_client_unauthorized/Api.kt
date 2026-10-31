suspend fun proxy(call: ApplicationCall) {
    try {
        call.respondText(rest.getForObject(BILLING, String::class.java)!!)
    } catch (e: HttpClientErrorException.Unauthorized) {
        call.respondText(e.message ?: "") // EXPECT: finding tp-kotlin-outbound-unauthorized
    }
}
