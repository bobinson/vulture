public class LogInterceptor implements HandlerInterceptor {
  public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
    if (request.getHeader("X-Debug") != null) {
      return true;
    }
    log.info("req");
    return true;
  }
}
