package com.network.analyzer.configuration;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AccessOriginFilter implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void destroy() {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        if (req.getHeader("Origin") == null)
            res.setHeader("Access-Control-Allow-Origin", "*");
        else
            res.setHeader("Access-Control-Allow-Origin", req.getHeader("Origin"));

        if (req.getHeader("Access-Control-Request-Headers") == null)
            res.setHeader("Access-Control-Allow-Headers", "*");
        else
            res.setHeader("Access-Control-Allow-Headers", req.getHeader("Access-Control-Request-Headers"));

        res.setHeader("Access-Control-Allow-Methods", "POST,OPTIONS,GET,PUT,PATCH,DELETE");
        res.setHeader("Access-Control-Allow-Credentials", "true");

        if (req.getMethod().equalsIgnoreCase("options")) {
            res.setStatus(200);
            return;
        }

        filterChain.doFilter(servletRequest, servletResponse);
    }
}
