package com.commerce.auth.integration;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 17:36
Version 1.0
*/

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.config.enums.RoleName;
import com.commerce.auth.entity.User;
import com.commerce.auth.repository.UserRepository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MvcResult;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class RegistrationIntegrationTest {
    @Autowired
    private JdbcTemplate jdbcTemplate;

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
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TransactionTemplate transactionTemplate;

    private static final String PASSWORD = "SecurePassword123!";

    private String uniqueUsername() {
        return "user" + UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 12);
    }

    private String emailFor(String username) {
        return username + "@example.com";
    }

    private String registerJson(String username, String email) {
        return """
                {
                    "username": "%s",
                    "email": "%s",
                    "password": "%s"
                }
                """.formatted(username, email, PASSWORD);
    }

    private User registerAndFindUser(
            String username,
            String email
    ) throws Exception {

        mockMvc.perform(
                        post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(registerJson(username, email))
                )
                .andExpect(status().isCreated());

        return userRepository.findByEmail(email)
                .orElseThrow(() ->
                        new AssertionError(
                                "Registered user not found"
                        )
                );
    }

    // TEST 1: Registration persists a real user

    @Test
    void register_whenValid_shouldPersistUser()
            throws Exception {

        String username = uniqueUsername();
        String email = emailFor(username);

        User savedUser = registerAndFindUser(
                username, email
        );

        assertNotNull(savedUser.getId());
        assertEquals(username, savedUser.getUsername());
        assertEquals(email, savedUser.getEmail());
    }

    // TEST 2: Registration assigns USER role

    @Test
    void register_whenValid_shouldAssignDefaultUserRole()
            throws Exception {

        String username = uniqueUsername();
        String email = emailFor(username);

        registerAndFindUser(username, email);

        Boolean validRole = transactionTemplate.execute(
                status -> {

                    User user = userRepository.findByEmail(email)
                            .orElseThrow();

                    return user.getRoles().size() == 1
                            && user.getRoles().stream()
                            .anyMatch(role ->
                                    role.getName() == RoleName.USER
                            );
                }
        );

        assertEquals(Boolean.TRUE, validRole);
    }

    // TEST 3: Password is stored as a hash

    @Test
    void register_whenValid_shouldStoreHashedPassword()
            throws Exception {

        String username = uniqueUsername();
        String email = emailFor(username);

        User savedUser = registerAndFindUser(
                username, email
        );

        String storedPassword = savedUser.getPassword();

        assertNotNull(storedPassword);
        assertNotEquals(PASSWORD, storedPassword);

        assertTrue(
                passwordEncoder.matches(
                        PASSWORD,
                        storedPassword
                )
        );
    }

    private long countUsersByEmail(String email) {
        Long count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM users WHERE email = ?",
                Long.class,
                email
        );

        return count == null ? 0L : count;
    }

    private MvcResult performRegistration(
            String username,
            String email
    ) throws Exception {

        return mockMvc.perform(
                post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(username, email))
        ).andReturn();
    }

    @Test
    void register_whenEmailAlreadyExists_shouldRejectSecondRegistration()
            throws Exception {

        // Arrange
        String email = "duplicate-" + UUID.randomUUID() + "@example.com";

        String firstUsername = uniqueUsername();
        String secondUsername = uniqueUsername();

        // Act - First registration
        mockMvc.perform(
                        post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(registerJson(firstUsername, email))
                )
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").value("201"));

        // Act - Second registration with duplicate email
        mockMvc.perform(
                        post("/api/auth/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(registerJson(secondUsername, email))
                )
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("409"))
                .andExpect(jsonPath("$.message")
                        .value("Email already registered"));

        // Assert - Database integrity
        assertEquals(
                1L,
                countUsersByEmail(email),
                "Only one user should exist with the same email"
        );

        assertTrue(
                userRepository.findByUsername(firstUsername).isPresent(),
                "First user should be registered"
        );

        assertTrue(
                userRepository.findByUsername(secondUsername).isEmpty(),
                "Second user should not be registered"
        );
    }

    @Test
    void register_whenConcurrentRequestsUseSameEmail_shouldCreateOnlyOneUser()
            throws Exception {

        // Arrange
        String email = "concurrent-" + UUID.randomUUID() + "@example.com";

        String username1 = uniqueUsername();
        String username2 = uniqueUsername();

        ExecutorService executor = Executors.newFixedThreadPool(2);

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        try {

            // Act - First request
            Future<Integer> first = executor.submit(() -> {

                ready.countDown();

                if (!start.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException(
                            "Timed out waiting for start signal"
                    );
                }

                MvcResult result = performRegistration(
                        username1,
                        email
                );

                return result.getResponse().getStatus();
            });

            // Act - Second request
            Future<Integer> second = executor.submit(() -> {

                ready.countDown();

                if (!start.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException(
                            "Timed out waiting for start signal"
                    );
                }

                MvcResult result = performRegistration(
                        username2,
                        email
                );

                return result.getResponse().getStatus();
            });

            // Wait until both requests are ready
            assertTrue(
                    ready.await(10, TimeUnit.SECONDS),
                    "Both requests should be ready"
            );

            // Start simultaneously
            start.countDown();

            int status1 = first.get(30, TimeUnit.SECONDS);
            int status2 = second.get(30, TimeUnit.SECONDS);

            // Assert - HTTP status
            long successfulRequests = java.util.stream.Stream
                    .of(status1, status2)
                    .filter(status -> status == 201)
                    .count();

            long conflictRequests = java.util.stream.Stream
                    .of(status1, status2)
                    .filter(status -> status == 409)
                    .count();

            assertEquals(
                    1L,
                    successfulRequests,
                    "Exactly one registration must succeed"
            );

            assertEquals(
                    1L,
                    conflictRequests,
                    "Exactly one registration must return 409 Conflict"
            );

            // Assert - Database integrity
            assertEquals(
                    1L,
                    countUsersByEmail(email),
                    "Database must contain exactly one account"
            );

            long registeredUsernames = java.util.stream.Stream
                    .of(username1, username2)
                    .filter(username ->
                            userRepository.findByUsername(username).isPresent()
                    )
                    .count();

            assertEquals(
                    1L,
                    registeredUsernames,
                    "Only one username should be registered"
            );

        } finally {

            start.countDown();
            executor.shutdownNow();

        }
    }

    @Test
    void register_whenEmailDiffersOnlyByCase_shouldReturn409()
            throws Exception {

        String id = UUID.randomUUID().toString().substring(0, 8);

        String originalEmail = "career-" + id + "@example.com";
        String uppercaseEmail = originalEmail.toUpperCase();

        String username1 = uniqueUsername();
        String username2 = uniqueUsername();

        mockMvc.perform(
                post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(username1, originalEmail))
        ).andExpect(status().isCreated());

        mockMvc.perform(
                post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerJson(username2, uppercaseEmail))
        ).andExpect(status().isConflict());

        assertEquals(
                1L,
                countUsersByEmail(originalEmail)
        );

        assertTrue(
                userRepository.findByUsername(username2).isEmpty()
        );
    }

    @Test
    void register_whenValid_shouldPersistPendingVerificationStatus()
            throws Exception {

        String username = uniqueUsername();
        String email = emailFor(username);

        User savedUser = registerAndFindUser(username, email);

        assertEquals(
                AccountStatus.PENDING_VERIFICATION,
                savedUser.getAccountStatus()
        );

        assertEquals(Boolean.FALSE, savedUser.getEnabled());
        assertEquals(Boolean.FALSE, savedUser.getEmailVerified());
    }
}
