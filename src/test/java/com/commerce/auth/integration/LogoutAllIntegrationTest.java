package com.commerce.auth.integration;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 21:28
Version 1.0
*/

import com.commerce.auth.dto.request.RefreshTokenRequest;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.UnauthorizedException;
import com.commerce.auth.repository.RefreshTokenRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.security.jwt.JwtService;
import com.commerce.auth.service.AuthService;
import com.commerce.auth.service.EmailVerificationService;
import com.commerce.auth.service.RefreshTokenService;
import com.commerce.auth.utils.TokenHasher;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class LogoutAllIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres =
            new PostgreSQLContainer("postgres:16-alpine")
                    .withDatabaseName("careertrack_test")
                    .withUsername("test")
                    .withPassword("test");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private EmailVerificationService verificationService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthService authService;

    @Autowired
    private TransactionTemplate transactionTemplate;

    private User createActiveUser() throws Exception {

        String unique = UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 12);

        String username = "user" + unique;
        String email = username + "@example.com";

        String registerJson = """
                {
                    "username": "%s",
                    "email": "%s",
                    "password": "SecurePassword123!"
                }
                """.formatted(username, email);

        mockMvc.perform(
                post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson)
        ).andExpect(status().isCreated());

        User user = userRepository.findByEmail(email)
                .orElseThrow();

        String rawToken =
                verificationService.createVerificationToken(user);

        String verifyJson = """
                {"token": "%s"}
                """.formatted(rawToken);

        mockMvc.perform(
                post("/api/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyJson)
        ).andExpect(status().isOk());

        return userRepository.findById(user.getId())
                .orElseThrow();
    }

    private Authentication authenticationFor(User user) {
        return new UsernamePasswordAuthenticationToken(
                user.getUsername(),
                null,
                List.of()
        );
    }

    private String createStoredRefreshToken(User user) {

        String token = jwtService.generateRefreshToken(user);

        refreshTokenService.create(
                user,
                token,
                "Integration Test",
                "127.0.0.1"
        );

        return token;
    }

    private void performLogoutAll(String accessToken)
            throws Exception {

        mockMvc.perform(
                        post("/api/auth/logout-all")
                                .header(
                                        "Authorization",
                                        "Bearer " + accessToken
                                )
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("200"));
    }

    // ======================================================
    // TEST 1 — REVOKE ALL SESSIONS
    // ======================================================

    @Test
    void logoutAll_shouldIncrementVersionAndRevokeAllTokens()
            throws Exception {

        User user = createActiveUser();

        Integer oldVersion = user.getTokenVersion();

        String accessToken =
                jwtService.generateAccessToken(user);

        String refreshToken1 =
                createStoredRefreshToken(user);

        String refreshToken2 =
                createStoredRefreshToken(user);

        assertNotEquals(refreshToken1, refreshToken2);

        assertEquals(
                2,
                refreshTokenRepository
                        .findAllByUserAndRevokedFalse(user)
                        .size()
        );

        performLogoutAll(accessToken);

        User updatedUser = userRepository.findById(user.getId())
                .orElseThrow();

        assertEquals(
                oldVersion + 1,
                updatedUser.getTokenVersion()
        );

        assertTrue(
                refreshTokenRepository
                        .findAllByUserAndRevokedFalse(updatedUser)
                        .isEmpty()
        );

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        "Bearer " + accessToken
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // ======================================================
    // TEST 2 — OLD REFRESH TOKEN REJECTED
    // ======================================================

    @Test
    void logoutAll_whenUsingOldRefreshToken_shouldReject()
            throws Exception {

        User user = createActiveUser();

        String accessToken =
                jwtService.generateAccessToken(user);

        String refreshToken =
                createStoredRefreshToken(user);

        performLogoutAll(accessToken);

        assertThrows(
                UnauthorizedException.class,
                () -> authService.refreshToken(
                        new RefreshTokenRequest(refreshToken),
                        new MockHttpServletRequest()
                )
        );

        assertTrue(
                refreshTokenRepository
                        .findByTokenHash(
                                TokenHasher.sha256(refreshToken)
                        )
                        .orElseThrow()
                        .getRevoked()
        );
    }

    // ======================================================
    // TEST 3 — TRANSACTION ROLLBACK
    // ======================================================

    @Test
    void logoutAll_whenTransactionFails_shouldRollback()
            throws Exception {

        User user = createActiveUser();

        Integer originalVersion = user.getTokenVersion();

        String refreshToken =
                createStoredRefreshToken(user);

        assertThrows(
                IllegalStateException.class,
                () -> transactionTemplate.executeWithoutResult(
                        status -> {

                            authService.logoutAll(
                                    authenticationFor(user)
                            );

                            throw new IllegalStateException(
                                    "Simulated transaction failure"
                            );
                        }
                )
        );

        User reloaded = userRepository.findById(user.getId())
                .orElseThrow();

        assertEquals(
                originalVersion,
                reloaded.getTokenVersion()
        );

        assertFalse(
                refreshTokenRepository
                        .findByTokenHash(
                                TokenHasher.sha256(refreshToken)
                        )
                        .orElseThrow()
                        .getRevoked()
        );
    }

    // ======================================================
    // TEST 4 — CONCURRENT LOGOUT ALL
    // ======================================================

    @Test
    void logoutAll_whenConcurrentRequests_shouldNotLoseVersionUpdate()
            throws Exception {

        User user = createActiveUser();

        Integer originalVersion = user.getTokenVersion();

        String refreshToken =
                createStoredRefreshToken(user);

        ExecutorService executor =
                Executors.newFixedThreadPool(2);

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        try {

            Callable<Boolean> task = () -> {

                ready.countDown();

                if (!start.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException(
                            "Concurrent test start timeout"
                    );
                }

                authService.logoutAll(
                        authenticationFor(user)
                );

                return true;
            };

            Future<Boolean> first = executor.submit(task);
            Future<Boolean> second = executor.submit(task);

            assertTrue(
                    ready.await(10, TimeUnit.SECONDS)
            );

            start.countDown();

            assertTrue(first.get(30, TimeUnit.SECONDS));
            assertTrue(second.get(30, TimeUnit.SECONDS));

            User reloaded = userRepository.findById(user.getId())
                    .orElseThrow();

            assertEquals(
                    originalVersion + 2,
                    reloaded.getTokenVersion()
            );

            assertTrue(
                    refreshTokenRepository
                            .findByTokenHash(
                                    TokenHasher.sha256(refreshToken)
                            )
                            .orElseThrow()
                            .getRevoked()
            );

        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }

    // ======================================================
    // TEST 5 — USER SESSION ISOLATION
    // ======================================================

    @Test
    void logoutAll_shouldNotRevokeOtherUsersSessions()
            throws Exception {

        User userA = createActiveUser();
        User userB = createActiveUser();

        String accessTokenA =
                jwtService.generateAccessToken(userA);

        String accessTokenB =
                jwtService.generateAccessToken(userB);

        String refreshTokenA =
                createStoredRefreshToken(userA);

        String refreshTokenB =
                createStoredRefreshToken(userB);

        performLogoutAll(accessTokenA);

        assertTrue(
                refreshTokenRepository
                        .findByTokenHash(
                                TokenHasher.sha256(refreshTokenA)
                        )
                        .orElseThrow()
                        .getRevoked()
        );

        assertFalse(
                refreshTokenRepository
                        .findByTokenHash(
                                TokenHasher.sha256(refreshTokenB)
                        )
                        .orElseThrow()
                        .getRevoked()
        );

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        "Bearer " + accessTokenB
                                )
                )
                .andExpect(status().isOk());
    }
}
