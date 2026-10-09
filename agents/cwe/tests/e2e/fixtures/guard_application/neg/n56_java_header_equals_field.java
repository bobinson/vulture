public class F extends OncePerRequestFilter {
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) {
    if (req.getHeader("X-Internal-Token").equals(token)) {
      chain.doFilter(req, res);
      return;
    }
    if (req.getSession(false) == null) { res.sendError(HttpServletResponse.SC_UNAUTHORIZED); return; }
    chain.doFilter(req, res);
  }
}
