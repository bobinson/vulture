@RestController
public class ShareController {
    @PostMapping("/share")
    public ResponseEntity<Void> share(@RequestBody ShareRequest req) {
        if (!validateSecret(req)) {
            throw new BadRequestException("invalid");
        }
        mailer.sendEmail(req.getRecipientEmail(), store(req));
        return ResponseEntity.ok().build();
    }
}
