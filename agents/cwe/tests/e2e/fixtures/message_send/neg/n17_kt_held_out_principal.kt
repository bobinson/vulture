package demo

class TeamController(private val mailer: InviteMailer) {

    fun invite(form: InviteForm, principal: Principal): Reply {
        val email = form.email.trim()
        mailer.sendInvitation(to = email, from = principal.name)
        return Reply.accepted()
    }
}
