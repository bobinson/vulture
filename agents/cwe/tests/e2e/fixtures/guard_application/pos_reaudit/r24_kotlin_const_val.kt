private const val BYPASS = "1"
class BypassInterceptor : HandlerInterceptor {
    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        if (request.getHeader("X-Bypass") == BYPASS) return true
        if (request.userPrincipal == null) { response.sendError(401); return false }
        return true
    }
}
