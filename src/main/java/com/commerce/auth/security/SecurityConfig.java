package com.commerce.auth.security;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:19
Version 1.0
*/

import com.commerce.auth.security.jwt.JwtAuthenticationFilter;
import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http)
            throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )
                .authorizeHttpRequests(auth -> auth

                        // Izinkan error dispatch Spring Boot
                        .dispatcherTypeMatchers(DispatcherType.ERROR)
                        .permitAll()

                        // JWKS public key endpoint
                        .requestMatchers(
                                HttpMethod.GET,
                                "/.well-known/jwks.json"
                        ).permitAll()

                        // Public authentication endpoints
                        .requestMatchers(
                                "/api/auth/login",
                                "/api/auth/register",
                                "/api/auth/refresh",
                                "/api/auth/verify-email",
                                "/v3/api-docs/**",
                                "/swagger-ui/**",
                                "/swagger-ui.html"
                        ).permitAll()

                        .requestMatchers("/api/admin/**")
                        .hasRole("ADMIN")

                        .requestMatchers("/api/career/**")
                        .hasRole("USER")
                        .requestMatchers(
                                HttpMethod.GET,
                                "/actuator/health",
                                "/actuator/health/liveness",
                                "/actuator/health/readiness"
                        ).permitAll()

                        .anyRequest()
                        .authenticated()
                )
                .addFilterBefore(
                        jwtAuthenticationFilter,
                        UsernamePasswordAuthenticationFilter.class
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(
                                (request, response, authException) ->
                                        response.sendError(
                                                HttpServletResponse.SC_UNAUTHORIZED
                                        )
                        )
                        .accessDeniedHandler(
                                (request, response, accessDeniedException) ->
                                        response.sendError(
                                                HttpServletResponse.SC_FORBIDDEN
                                        )
                        )
                );

        return http.build();
    }

}