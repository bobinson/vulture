fun Route.items() {
    get("/x") {
        try { svc.load() } catch (e: Exception) {
            // EXPECT-NEXT: finding  Kotlin property form of getLocalizedMessage
            call.respondText(e.localizedMessage)
        }
    }
}
