package com.commerce.auth.security.jwt;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 21:00
Version 1.0
*/

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.entity.User;

import io.jsonwebtoken.Claims;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtServiceImplTest {

    private static final String TEST_SECRET =
            "0123456789abcdef0123456789abcdef" +
                    "0123456789abcdef0123456789abcdef";

    @Mock
    private JwtProperties jwtProperties;

    @InjectMocks
    private JwtServiceImpl jwtService;

    @BeforeEach
    void setUp() {
        when(jwtProperties.getSecret())
                .thenReturn(TEST_SECRET);
    }

    private void stubAccessExpiration() {
        when(jwtProperties.getAccessTokenExpiration())
                .thenReturn(900_000L);
    }

    private void stubRefreshExpiration() {
        when(jwtProperties.getRefreshTokenExpiration())
                .thenReturn(604_800_000L);
    }

    private User activeUser() {
        return User.builder()
                .username("dhito")
                .tokenVersion(0)
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();
    }

    @Test
    void generateRefreshToken_shouldIncludeVersionAndJti() {

        stubRefreshExpiration();
        User user = activeUser();

        String token = jwtService.generateRefreshToken(user);
        Claims claims = jwtService.extractAllClaims(token);

        assertEquals("REFRESH", claims.get("type", String.class));
        assertEquals(0, claims.get("tokenVersion", Integer.class));
        assertNotNull(claims.getId());
        assertFalse(claims.getId().isBlank());
    }

    @Test
    void generateRefreshToken_shouldGenerateUniqueTokens() {

        stubRefreshExpiration();
        User user = activeUser();

        String first = jwtService.generateRefreshToken(user);
        String second = jwtService.generateRefreshToken(user);

        assertNotEquals(first, second);

        assertNotEquals(
                jwtService.extractAllClaims(first).getId(),
                jwtService.extractAllClaims(second).getId()
        );
    }

    @Test
    void refreshToken_whenTokenVersionChanges_shouldReject() {

        stubRefreshExpiration();
        User user = activeUser();

        String token = jwtService.generateRefreshToken(user);

        assertTrue(jwtService.isRefreshTokenValid(token, user));

        user.setTokenVersion(1);

        assertFalse(jwtService.isRefreshTokenValid(token, user));
    }

    @Test
    void refreshToken_shouldNotBeValidAsAccessToken() {

        stubRefreshExpiration();
        User user = activeUser();

        String refreshToken =
                jwtService.generateRefreshToken(user);

        assertFalse(jwtService.isTokenValid(refreshToken, user));
    }

    @Test
    void accessToken_shouldNotBeValidAsRefreshToken() {

        stubAccessExpiration();
        User user = activeUser();

        String accessToken =
                jwtService.generateAccessToken(user);

        assertFalse(jwtService.isRefreshTokenValid(accessToken, user));
    }

    @Test
    void tokens_whenAccountSuspended_shouldBeRejected() {

        stubAccessExpiration();
        stubRefreshExpiration();

        User user = activeUser();

        String accessToken = jwtService.generateAccessToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        user.setAccountStatus(AccountStatus.SUSPENDED);
        user.setEnabled(false);

        assertFalse(jwtService.isTokenValid(accessToken, user));

        assertFalse(
                jwtService.isRefreshTokenValid(refreshToken, user)
        );
    }
}
