public class ApiVersionInterceptor implements HandlerInterceptor {
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        if ("v2".equals(request.getHeader("X-Api-Version"))) {
            return true;
        }
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "unsupported api version");
        return false;
    }
}
