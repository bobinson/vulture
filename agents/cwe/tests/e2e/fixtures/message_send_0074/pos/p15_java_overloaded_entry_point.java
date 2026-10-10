@RestController
public class InviteController {
    @GetMapping("/invite")
    public void invite(InviteQuery q) {
        mailer.sendEmail(q.getEmail(), "You are invited");
    }

    public void inviteAll(List<String> emails) {
        for (String e : emails) invite(e);
    }

    private void invite(String email) {
        audit.log(email);
    }
}
