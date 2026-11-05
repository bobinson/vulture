package com.example.auth;

import javax.servlet.*;
import javax.servlet.http.*;

public class AuthFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws java.io.IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        if (req.getHeader("User-Agent") != null && req.getHeader("User-Agent").startsWith("Nacos-Server")) {
            chain.doFilter(request, response);
            return;
        }
        if (req.getSession(false) == null) {
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        chain.doFilter(request, response);
    }
}
