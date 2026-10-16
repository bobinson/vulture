public class AuthFilter implements Filter {
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) req;
    if (StringUtils.equals(request.getHeader("X-Internal"), "true")) {
      chain.doFilter(req, res);
      return;
    }
    ((HttpServletResponse) res).sendError(401);
  }
}
