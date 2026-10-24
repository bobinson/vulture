package demo;

public class SignupController {
    private final Mailer mailer;

    public SignupController(Mailer mailer) {
        this.mailer = mailer;
    }

    public Response invite(InviteForm form) {
        String email = form.getEmail();
        mailer.sendInvitation(email, "Join us");
        return Response.ok();
    }
}
