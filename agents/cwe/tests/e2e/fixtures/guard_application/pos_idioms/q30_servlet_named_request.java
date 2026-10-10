public class AuthFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest httpReq, HttpServletResponse httpRes, FilterChain chain) throws IOException, ServletException {
        if ("true".equals(httpReq.getHeader("X-Internal"))) {
            chain.doFilter(httpReq, httpRes);
            return;
        }
        if (httpReq.getSession().getAttribute("user") == null) {
            httpRes.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        chain.doFilter(httpReq, httpRes);
    }
}
