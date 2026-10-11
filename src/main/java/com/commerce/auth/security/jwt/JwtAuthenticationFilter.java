package com.commerce.auth.security.jwt;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:55
Version 1.0
*/

import com.commerce.auth.security.CustomUserDetailsService;
import com.commerce.auth.security.UserPrincipal;

import io.jsonwebtoken.JwtException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.RequiredArgsConstructor;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null
                || !authHeader.startsWith(BEARER_PREFIX)) {

            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(BEARER_PREFIX.length());

        try {

            String username = jwtService.extractUsername(token);

            if (username != null
                    && SecurityContextHolder.getContext()
                    .getAuthentication() == null) {

                UserPrincipal principal =
                        (UserPrincipal) userDetailsService
                                .loadUserByUsername(username);

                boolean accountActive =
                        principal.getUser().isAccountActive();

                if (accountActive
                        && jwtService.isTokenValid(
                        token,
                        principal.getUser()
                )) {

                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    principal,
                                    null,
                                    principal.getAuthorities()
                            );

                    authentication.setDetails(
                            new WebAuthenticationDetailsSource()
                                    .buildDetails(request)
                    );

                    SecurityContextHolder.getContext()
                            .setAuthentication(authentication);
                }
            }

        } catch (JwtException
                 | IllegalArgumentException
                 | UsernameNotFoundException ex) {

            // Invalid, expired, or unknown-user token.
            // Do not authenticate the request.
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }
}