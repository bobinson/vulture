package demo;

public class InviteController {
    private final Mailer mailer;

    public Response invite(InviteQuery q) {
        String email = q.getEmail();
        mailer.sendInvitationEmail(email);
        return Response.accepted();
    }
}
