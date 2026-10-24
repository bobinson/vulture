public class ServiceAuthFilter extends OncePerRequestFilter {
  @Value("${internal.token}") private String internalToken;
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws IOException, ServletException {
    if (internalToken.equals(req.getHeader("X-Internal-Token"))) {
      chain.doFilter(req, res);
      return;
    }
    res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }
}
