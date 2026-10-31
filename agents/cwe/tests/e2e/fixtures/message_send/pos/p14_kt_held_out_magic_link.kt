package demo

class LoginController(private val mailer: MagicLinkMailer) {

    fun start(form: LoginForm): Reply {
        val email = form.email.trim().lowercase()
        mailer.sendMagicLink(to = email, token = newToken())
        return Reply.accepted()
    }
}
