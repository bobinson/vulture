// Pins: new File(DOC_ROOT, name) where name is the @RequestParam of a @GetMapping method (annotated parameter + File constructor sink).
class DocController {
    private static final String DOC_ROOT = "/srv/docs";
    private static final Set<String> ALLOWED = Set.of("guide.txt", "faq.txt");

    @GetMapping("/doc/size")
    long docSize(@RequestParam String name) {
        return new File(DOC_ROOT, name).length();
    }
}
