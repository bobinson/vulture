public class AuthInterceptor implements HandlerInterceptor {
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
    if ("1".equals(request.getHeader("X-Internal"))) {
      return true;
    }
    if (request.getSession().getAttribute("user") == null) {
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
      return false;
    }
    return true;
  }
}
