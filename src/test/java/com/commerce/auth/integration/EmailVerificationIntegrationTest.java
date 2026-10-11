package com.commerce.auth.integration;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 20:36
Version 1.0
*/

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.dto.request.RefreshTokenRequest;
import com.commerce.auth.entity.RefreshToken;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.UnauthorizedException;
import com.commerce.auth.repository.RefreshTokenRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.security.jwt.JwtService;
import com.commerce.auth.service.AuthService;
import com.commerce.auth.service.EmailVerificationService;
import com.commerce.auth.service.RefreshTokenService;
import com.commerce.auth.utils.TokenHasher;
import com.commerce.auth.utils.VerificationTokenUtils;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class EmailVerificationIntegrationTest {

    private static final String VERIFY_URL =
            "/api/auth/verify-email";

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
    private EmailVerificationService verificationService;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private record VerificationFixture(
            UUID userId,
            String rawToken,
            String tokenHash
    ) {}

    private VerificationFixture createPendingUserWithToken()
            throws Exception {

        String unique = UUID.randomUUID()
                .toString()
                .replace("-", "");

        String username = "user" + unique.substring(0, 12);
        String email = username + "@example.com";

        String registrationJson = """
                {
                    "username": "%s",
                    "email": "%s",
                    "password": "SecurePassword123!"
                }
                """.formatted(username, email);

        mockMvc.perform(
                post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registrationJson)
        ).andExpect(status().isCreated());

        User user = userRepository.findByEmail(email)
                .orElseThrow();

        // Fixture manual sementara.
        // Registration belum terintegrasi dengan token delivery.
        String rawToken =
                verificationService.createVerificationToken(user);

        return new VerificationFixture(
                user.getId(),
                rawToken,
                VerificationTokenUtils.hashToken(rawToken)
        );
    }

    private org.springframework.test.web.servlet.ResultActions
    verifyRequest(String rawToken) throws Exception {

        String json = """
                {"token":"%s"}
                """.formatted(rawToken);

        return mockMvc.perform(
                post(VERIFY_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json)
        );
    }

    private User reloadUser(UUID userId) {
        return userRepository.findById(userId)
                .orElseThrow();
    }

    private LocalDateTime getUsedAt(String tokenHash) {
        return jdbcTemplate.queryForObject(
                """
                SELECT used_at
                FROM email_verification_tokens
                WHERE token_hash = ?
                """,
                LocalDateTime.class,
                tokenHash
        );
    }

    // 1. VALID TOKEN

    @Test
    void verifyEmail_whenTokenValid_shouldActivateUser()
            throws Exception {

        VerificationFixture fixture =
                createPendingUserWithToken();

        verifyRequest(fixture.rawToken())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("200"));

        User user = reloadUser(fixture.userId());

        assertEquals(
                AccountStatus.ACTIVE,
                user.getAccountStatus()
        );

        assertTrue(user.getEnabled());
        assertTrue(user.getEmailVerified());

        assertNotNull(getUsedAt(fixture.tokenHash()));
    }

    // 2. TOKEN REUSE

    @Test
    void verifyEmail_whenTokenUsedTwice_shouldRejectSecondRequest()
            throws Exception {

        VerificationFixture fixture =
                createPendingUserWithToken();

        verifyRequest(fixture.rawToken())
                .andExpect(status().isOk());

        LocalDateTime firstUsedAt =
                getUsedAt(fixture.tokenHash());

        verifyRequest(fixture.rawToken())
                .andExpect(status().isBadRequest());

        assertEquals(
                firstUsedAt,
                getUsedAt(fixture.tokenHash())
        );

        assertEquals(
                AccountStatus.ACTIVE,
                reloadUser(fixture.userId()).getAccountStatus()
        );
    }

    // 3. EXPIRED TOKEN

    @Test
    void verifyEmail_whenTokenExpired_shouldRejectRequest()
            throws Exception {

        VerificationFixture fixture =
                createPendingUserWithToken();

        jdbcTemplate.update(
                """
                UPDATE email_verification_tokens
                SET expired_at = ?
                WHERE token_hash = ?
                """,
                LocalDateTime.now(ZoneOffset.UTC).minusMinutes(1),
                fixture.tokenHash()
        );

        verifyRequest(fixture.rawToken())
                .andExpect(status().isBadRequest());

        assertEquals(
                AccountStatus.PENDING_VERIFICATION,
                reloadUser(fixture.userId()).getAccountStatus()
        );

        assertNull(getUsedAt(fixture.tokenHash()));
    }

    // 4. REVOKED TOKEN

    @Test
    void verifyEmail_whenTokenRevoked_shouldRejectRequest()
            throws Exception {

        VerificationFixture fixture =
                createPendingUserWithToken();

        jdbcTemplate.update(
                """
                UPDATE email_verification_tokens
                SET revoked = TRUE
                WHERE token_hash = ?
                """,
                fixture.tokenHash()
        );

        verifyRequest(fixture.rawToken())
                .andExpect(status().isBadRequest());

        assertEquals(
                AccountStatus.PENDING_VERIFICATION,
                reloadUser(fixture.userId()).getAccountStatus()
        );

        assertNull(getUsedAt(fixture.tokenHash()));
    }

    // 5. SUSPENDED USER

    @Test
    void verifyEmail_whenUserSuspended_shouldNotActivate()
            throws Exception {

        VerificationFixture fixture =
                createPendingUserWithToken();

        jdbcTemplate.update(
                """
                UPDATE users
                SET account_status = 'SUSPENDED',
                    enabled = FALSE
                WHERE id = ?
                """,
                fixture.userId()
        );

        verifyRequest(fixture.rawToken())
                .andExpect(status().isBadRequest());

        User user = reloadUser(fixture.userId());

        assertEquals(
                AccountStatus.SUSPENDED,
                user.getAccountStatus()
        );

        assertFalse(user.getEnabled());
        assertFalse(user.getEmailVerified());

        assertNull(getUsedAt(fixture.tokenHash()));
    }

    // 6. CONCURRENT TOKEN VERIFICATION

    @Test
    void verifyEmail_whenConcurrentRequests_shouldAllowOnlyOneSuccess()
            throws Exception {

        VerificationFixture fixture =
                createPendingUserWithToken();

        ExecutorService executor =
                Executors.newFixedThreadPool(2);

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        try {

            java.util.concurrent.Callable<Integer> task = () -> {

                ready.countDown();

                if (!start.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException(
                            "Start signal timeout"
                    );
                }

                return verifyRequest(fixture.rawToken())
                        .andReturn()
                        .getResponse()
                        .getStatus();
            };

            Future<Integer> first = executor.submit(task);
            Future<Integer> second = executor.submit(task);

            assertTrue(
                    ready.await(10, TimeUnit.SECONDS)
            );

            start.countDown();

            int status1 = first.get(30, TimeUnit.SECONDS);
            int status2 = second.get(30, TimeUnit.SECONDS);

            long successCount = IntStream
                    .of(status1, status2)
                    .filter(status -> status == 200)
                    .count();

            long rejectedCount = IntStream
                    .of(status1, status2)
                    .filter(status -> status == 400)
                    .count();

            assertEquals(1L, successCount);
            assertEquals(1L, rejectedCount);

            assertEquals(
                    AccountStatus.ACTIVE,
                    reloadUser(fixture.userId()).getAccountStatus()
            );

            assertNotNull(getUsedAt(fixture.tokenHash()));

        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }


    @Test
    void verifyEmail_whenTransactionFails_shouldRollbackAllChanges()
            throws Exception {

        // Arrange
        VerificationFixture fixture =
                createPendingUserWithToken();

        // Act: verification berhasil dijalankan dalam transaksi,
        // tetapi transaksi sengaja digagalkan sebelum commit.
        assertThrows(
                IllegalStateException.class,
                () -> transactionTemplate.executeWithoutResult(status -> {

                    verificationService.verifyEmail(fixture.rawToken());

                    throw new IllegalStateException(
                            "Simulated transaction failure"
                    );
                })
        );

        // Assert: user tetap belum terverifikasi
        User user = reloadUser(fixture.userId());

        assertEquals(
                AccountStatus.PENDING_VERIFICATION,
                user.getAccountStatus()
        );

        assertFalse(user.getEnabled());
        assertFalse(user.getEmailVerified());

        // Assert: token belum dianggap digunakan
        assertNull(getUsedAt(fixture.tokenHash()));
    }


    @Test
    void refreshToken_whenConcurrentRequests_shouldAllowOnlyOneSuccess()
            throws Exception {

        // 1. Create and activate a real user
        VerificationFixture fixture =
                createPendingUserWithToken();

        verifyRequest(fixture.rawToken())
                .andExpect(status().isOk());

        User user = reloadUser(fixture.userId());

        assertEquals(AccountStatus.ACTIVE, user.getAccountStatus());

        // 2. Issue a real refresh JWT
        String oldRefreshToken =
                jwtService.generateRefreshToken(user);

        refreshTokenService.create(
                user,
                oldRefreshToken,
                "Integration Test",
                "127.0.0.1"
        );

        // 3. Prepare two simultaneous refresh requests
        ExecutorService executor =
                Executors.newFixedThreadPool(2);

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        try {

            Callable<Boolean> refreshTask = () -> {

                ready.countDown();

                if (!start.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException(
                            "Concurrent test start timeout"
                    );
                }

                try {

                    authService.refreshToken(
                            new RefreshTokenRequest(oldRefreshToken),
                            new MockHttpServletRequest()
                    );

                    return true;

                } catch (UnauthorizedException ex) {

                    return false;
                }
            };

            Future<Boolean> first =
                    executor.submit(refreshTask);

            Future<Boolean> second =
                    executor.submit(refreshTask);

            assertTrue(
                    ready.await(10, TimeUnit.SECONDS)
            );

            // 4. Release both threads together
            start.countDown();

            boolean firstSuccess =
                    first.get(30, TimeUnit.SECONDS);

            boolean secondSuccess =
                    second.get(30, TimeUnit.SECONDS);

            // 5. Exactly one refresh operation must succeed
            long successCount =
                    java.util.stream.Stream
                            .of(firstSuccess, secondSuccess)
                            .filter(Boolean::booleanValue)
                            .count();

            assertEquals(1L, successCount);

            // 6. Old token must be revoked
            RefreshToken storedToken =
                    refreshTokenRepository.findByTokenHash(
                            TokenHasher.sha256(oldRefreshToken)
                    ).orElseThrow();

            assertTrue(storedToken.getRevoked());

            // 7. Only one replacement refresh token remains active
            User reloadedUser = reloadUser(fixture.userId());

            assertEquals(
                    1,
                    refreshTokenRepository
                            .findAllByUserAndRevokedFalse(reloadedUser)
                            .size()
            );

        } finally {

            start.countDown();
            executor.shutdownNow();
        }
    }


// ==========================================================
// 1. ACTIVE USER + VALID ACCESS TOKEN
// ==========================================================

    @Test
    void protectedEndpoint_whenAccessTokenValid_shouldReturn200()
            throws Exception {

        VerificationFixture fixture = createPendingUserWithToken();

        verifyRequest(fixture.rawToken())
                .andExpect(status().isOk());

        User user = reloadUser(fixture.userId());

        String accessToken = jwtService.generateAccessToken(user);

        mockMvc.perform(
                        get("/api/auth/me")
                                .header("Authorization", "Bearer " + accessToken)
                )
                .andExpect(status().isOk());
    }


// ==========================================================
// 2. SUSPENDED USER + OLD ACCESS TOKEN
// ==========================================================

    @Test
    void protectedEndpoint_whenUserSuspended_shouldReturn401()
            throws Exception {

        VerificationFixture fixture = createPendingUserWithToken();

        verifyRequest(fixture.rawToken())
                .andExpect(status().isOk());

        User user = reloadUser(fixture.userId());

        String accessToken = jwtService.generateAccessToken(user);

        // Simulate CMS administrator suspending the account.
        jdbcTemplate.update(
                """
                UPDATE users
                SET account_status = 'SUSPENDED',
                    enabled = FALSE
                WHERE id = ?
                """,
                fixture.userId()
        );

        mockMvc.perform(
                        get("/api/auth/me")
                                .header("Authorization", "Bearer " + accessToken)
                )
                .andExpect(status().isUnauthorized());
    }


// ==========================================================
// 3. MALFORMED JWT
// ==========================================================

    @Test
    void protectedEndpoint_whenJwtMalformed_shouldReturn401()
            throws Exception {

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        "Bearer invalid.jwt.token"
                                )
                )
                .andExpect(status().isUnauthorized());
    }


// ==========================================================
// 4. REFRESH TOKEN CANNOT ACCESS PROTECTED API
// ==========================================================

    @Test
    void protectedEndpoint_whenUsingRefreshToken_shouldReturn401()
            throws Exception {

        VerificationFixture fixture = createPendingUserWithToken();

        verifyRequest(fixture.rawToken())
                .andExpect(status().isOk());

        User user = reloadUser(fixture.userId());

        String refreshToken = jwtService.generateRefreshToken(user);

        mockMvc.perform(
                        get("/api/auth/me")
                                .header("Authorization", "Bearer " + refreshToken)
                )
                .andExpect(status().isUnauthorized());
    }


// ==========================================================
// 5. REQUEST WITHOUT AUTHENTICATION
// ==========================================================

    @Test
    void protectedEndpoint_whenNoBearerToken_shouldReturn401()
            throws Exception {

        mockMvc.perform(
                        get("/api/auth/me")
                )
                .andExpect(status().isUnauthorized());
    }

}
