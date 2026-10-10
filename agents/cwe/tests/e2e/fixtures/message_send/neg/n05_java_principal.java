package demo;

import java.security.Principal;

public class ProfileController {
    private final Mailer mailer;

    public Response changeEmail(ChangeEmailForm form, Principal principal) {
        String email = form.getEmail();
        mailer.sendVerificationEmail(email, principal.getName());
        return Response.ok();
    }
}
