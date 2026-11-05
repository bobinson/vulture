public class AuthFilter implements Filter {
  private static final String INTERNAL = "true";
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    if (Objects.equals(request.getHeader("X-Internal"), INTERNAL)) {
      chain.doFilter(req, res);
      return;
    }
    ((HttpServletResponse) res).sendError(401);
  }
}
