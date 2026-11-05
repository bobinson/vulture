// Pins: an allowlist guard `if (!ALLOWED.contains(name)) throw ...` on the @RequestParam before new File(DOC_ROOT, name).
class DocController {
    private static final String DOC_ROOT = "/srv/docs";
    private static final Set<String> ALLOWED = Set.of("guide.txt", "faq.txt");

    @GetMapping("/doc/size")
    long docSize(@RequestParam String name) {
        if (!ALLOWED.contains(name)) throw new IllegalArgumentException("unknown doc");
        return new File(DOC_ROOT, name).length();
    }
}
