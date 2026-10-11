package com.commerce.auth.security.jwt;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 20:52
Version 1.0
*/

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.entity.User;
import com.commerce.auth.security.CustomUserDetailsService;
import com.commerce.auth.security.UserPrincipal;

import io.jsonwebtoken.MalformedJwtException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterTest {

    private static final String ACCESS_TOKEN = "test.access.token";

    @Mock
    private JwtService jwtService;

    @Mock
    private CustomUserDetailsService userDetailsService;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private User activeUser() {
        return User.builder()
                .username("dhito")
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();
    }

    private MockHttpServletRequest requestWithToken() {
        MockHttpServletRequest request =
                new MockHttpServletRequest();

        request.addHeader(
                "Authorization",
                "Bearer " + ACCESS_TOKEN
        );

        return request;
    }

    // 1. ACTIVE USER + VALID JWT

    @Test
    void filter_whenAccountActiveAndJwtValid_shouldAuthenticate()
            throws Exception {

        User user = activeUser();
        UserPrincipal principal = mock(UserPrincipal.class);

        when(jwtService.extractUsername(ACCESS_TOKEN))
                .thenReturn("dhito");

        when(userDetailsService.loadUserByUsername("dhito"))
                .thenReturn(principal);

        when(principal.getUser()).thenReturn(user);
        when(principal.getAuthorities())
                .thenReturn(Collections.emptyList());

        when(jwtService.isTokenValid(ACCESS_TOKEN, user))
                .thenReturn(true);

        jwtAuthenticationFilter.doFilter(
                requestWithToken(),
                new MockHttpServletResponse(),
                new MockFilterChain()
        );

        assertNotNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );

        verify(jwtService).isTokenValid(ACCESS_TOKEN, user);
    }

    // 2. SUSPENDED USER + PREVIOUSLY VALID JWT

    @Test
    void filter_whenAccountSuspended_shouldNotAuthenticate()
            throws Exception {

        User user = activeUser();

        user.setAccountStatus(AccountStatus.SUSPENDED);
        user.setEnabled(false);

        UserPrincipal principal = mock(UserPrincipal.class);

        when(jwtService.extractUsername(ACCESS_TOKEN))
                .thenReturn("dhito");

        when(userDetailsService.loadUserByUsername("dhito"))
                .thenReturn(principal);

        when(principal.getUser()).thenReturn(user);

        jwtAuthenticationFilter.doFilter(
                requestWithToken(),
                new MockHttpServletResponse(),
                new MockFilterChain()
        );

        assertNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );

        verify(jwtService, never())
                .isTokenValid(anyString(), any());
    }

    // 3. MALFORMED JWT

    @Test
    void filter_whenJwtMalformed_shouldNotAuthenticate()
            throws Exception {

        when(jwtService.extractUsername(ACCESS_TOKEN))
                .thenThrow(
                        new MalformedJwtException("Invalid JWT")
                );

        jwtAuthenticationFilter.doFilter(
                requestWithToken(),
                new MockHttpServletResponse(),
                new MockFilterChain()
        );

        assertNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );

        verifyNoInteractions(userDetailsService);
    }

    // 4. REQUEST WITHOUT BEARER TOKEN

    @Test
    void filter_whenAuthorizationHeaderMissing_shouldContinue()
            throws Exception {

        jwtAuthenticationFilter.doFilter(
                new MockHttpServletRequest(),
                new MockHttpServletResponse(),
                new MockFilterChain()
        );

        assertNull(
                SecurityContextHolder.getContext()
                        .getAuthentication()
        );

        verifyNoInteractions(jwtService, userDetailsService);
    }
}
