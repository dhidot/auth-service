package com.commerce.auth.integration;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:29
Version 1.0
*/

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.config.enums.RoleName;
import com.commerce.auth.entity.Role;
import com.commerce.auth.entity.User;
import com.commerce.auth.repository.RoleRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.security.jwt.JwtService;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "jwt.secret=CareerTrackTestOnlySecretKey_0123456789ABCDEF0123456789"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class MeEndpointIntegrationTest {

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
    private RoleRepository roleRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // =========================================================
    // TEST HELPERS
    // =========================================================

    private User createUser(RoleName roleName) {

        String suffix = UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 12);

        String username = "me" + suffix;

        Role role = roleRepository.findByName(roleName)
                .orElseThrow();

        User user = User.builder()
                .username(username)
                .email(username + "@example.com")
                .password(
                        passwordEncoder.encode("TestPassword123!")
                )
                .tokenVersion(0)
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();

        user.getRoles().add(role);

        return userRepository.saveAndFlush(user);
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }

    // =========================================================
    // TEST 1: USER SUCCESS CONTRACT
    // =========================================================

    @Test
    void activeUser_shouldReturnExactSuccessfulContract()
            throws Exception {

        User user = createUser(RoleName.USER);

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(
                                                jwtService.generateAccessToken(user)
                                        )
                                )
                )
                .andExpect(status().isOk())
                .andExpect(
                        content().contentTypeCompatibleWith(
                                MediaType.APPLICATION_JSON
                        )
                )
                .andExpect(jsonPath("$.code").value("200"))
                .andExpect(jsonPath("$.message").value("Success"))
                .andExpect(jsonPath("$.data", aMapWithSize(5)))
                .andExpect(
                        jsonPath("$.data.id")
                                .value(user.getId().toString())
                )
                .andExpect(
                        jsonPath("$.data.username")
                                .value(user.getUsername())
                )
                .andExpect(
                        jsonPath("$.data.email")
                                .value(user.getEmail())
                )
                .andExpect(
                        jsonPath("$.data.roles", contains("USER"))
                )
                .andExpect(
                        jsonPath("$.data.permissions", empty())
                );
    }

    // =========================================================
    // TEST 2: ADMIN SUCCESS CONTRACT
    // =========================================================

    @Test
    void activeAdmin_shouldReturnAdminRoleAndSevenPermissions()
            throws Exception {

        User admin = createUser(RoleName.ADMIN);

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(
                                                jwtService.generateAccessToken(admin)
                                        )
                                )
                )
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$.data.roles", contains("ADMIN"))
                )
                .andExpect(
                        jsonPath(
                                "$.data.permissions",
                                containsInAnyOrder(
                                        "ADMIN_USER_READ",
                                        "ADMIN_USER_UPDATE_STATUS",
                                        "ADMIN_SESSION_REVOKE",
                                        "ADMIN_DASHBOARD_READ",
                                        "ADMIN_AUDIT_READ",
                                        "ADMIN_ROLE_READ",
                                        "ADMIN_INTEGRATION_LOG_READ"
                                )
                        )
                );
    }

    // =========================================================
    // TEST 3: NO TOKEN
    // =========================================================

    @Test
    void withoutToken_shouldReturn401()
            throws Exception {

        mockMvc.perform(
                        get("/api/auth/me")
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 4: MALFORMED JWT
    // =========================================================

    @Test
    void malformedJwt_shouldReturn401()
            throws Exception {

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        "Bearer not.a.valid.jwt"
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 5: TAMPERED JWT SIGNATURE
    // =========================================================

    @Test
    void tamperedSignature_shouldReturn401()
            throws Exception {

        User user = createUser(RoleName.USER);

        String jwt = jwtService.generateAccessToken(user);

        String[] parts = jwt.split("\\.");

        char replacement =
                parts[2].charAt(0) == 'A' ? 'B' : 'A';

        String invalid =
                parts[0] + "." +
                        parts[1] + "." +
                        replacement +
                        parts[2].substring(1);

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(invalid)
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 6: EXPIRED JWT
    // =========================================================

    @Test
    void expiredJwt_shouldReturn401()
            throws Exception {

        User user = createUser(RoleName.USER);

        Instant now = Instant.now();

        String expiredJwt = Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getUsername())
                .claim("type", "ACCESS")
                .claim(
                        "tokenVersion",
                        user.getTokenVersion()
                )
                .issuedAt(
                        Date.from(
                                now.minusSeconds(7200)
                        )
                )
                .expiration(
                        Date.from(
                                now.minusSeconds(3600)
                        )
                )
                .signWith(
                        Keys.hmacShaKeyFor(
                                jwtProperties.getSecret()
                                        .getBytes(StandardCharsets.UTF_8)
                        )
                )
                .compact();

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(expiredJwt)
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 7: REFRESH JWT CANNOT ACCESS /ME
    // =========================================================

    @Test
    void refreshJwt_shouldNotAuthenticateMe()
            throws Exception {

        User user = createUser(RoleName.USER);

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(
                                                jwtService.generateRefreshToken(user)
                                        )
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 8: LOGOUT ALL INVALIDATES OLD ACCESS JWT
    // =========================================================

    @Test
    void oldAccessJwt_afterLogoutAll_shouldReturn401()
            throws Exception {

        User user = createUser(RoleName.USER);

        String oldJwt = jwtService.generateAccessToken(user);

        mockMvc.perform(
                        post("/api/auth/logout-all")
                                .header(
                                        "Authorization",
                                        bearer(oldJwt)
                                )
                )
                .andExpect(status().isOk());

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(oldJwt)
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 9: SUSPENDED USER
    // =========================================================

    @Test
    void suspendedAccount_withOldJwt_shouldReturn401()
            throws Exception {

        User user = createUser(RoleName.USER);

        String oldJwt = jwtService.generateAccessToken(user);

        jdbcTemplate.update(
                """
                UPDATE users
                SET account_status = 'SUSPENDED',
                    enabled = FALSE
                WHERE id = ?
                """,
                user.getId()
        );

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(oldJwt)
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 10: PENDING EMAIL VERIFICATION
    // =========================================================

    @Test
    void pendingVerificationAccount_shouldReturn401()
            throws Exception {

        User user = createUser(RoleName.USER);

        String oldJwt = jwtService.generateAccessToken(user);

        jdbcTemplate.update(
                """
                UPDATE users
                SET account_status = 'PENDING_VERIFICATION',
                    enabled = FALSE,
                    email_verified = FALSE
                WHERE id = ?
                """,
                user.getId()
        );

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(oldJwt)
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 11: UNKNOWN USER
    // =========================================================

    @Test
    void unknownUserToken_shouldReturn401()
            throws Exception {

        String suffix = UUID.randomUUID()
                .toString()
                .replace("-", "");

        // Validly signed token whose subject (a random UUID) is not in
        // the database, e.g. a deleted account.
        User neverPersisted = User.builder()
                .id(UUID.randomUUID())
                .username(
                        "ghost" + suffix.substring(0, 12)
                )
                .tokenVersion(0)
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(
                                                jwtService.generateAccessToken(
                                                        neverPersisted
                                                )
                                        )
                                )
                )
                .andExpect(status().isUnauthorized());
    }

    // =========================================================
    // TEST 12: SENSITIVE DATA MUST NOT BE EXPOSED
    // =========================================================

    @Test
    void successfulMeResponse_shouldNeverExposeCredentials()
            throws Exception {

        User user = createUser(RoleName.USER);

        mockMvc.perform(
                        get("/api/auth/me")
                                .header(
                                        "Authorization",
                                        bearer(
                                                jwtService.generateAccessToken(user)
                                        )
                                )
                )
                .andExpect(status().isOk())
                .andExpect(
                        jsonPath("$.data", aMapWithSize(5))
                )
                .andExpect(
                        jsonPath("$.data.password").doesNotExist()
                )
                .andExpect(
                        jsonPath("$.data.accessToken").doesNotExist()
                )
                .andExpect(
                        jsonPath("$.data.refreshToken").doesNotExist()
                )
                .andExpect(
                        jsonPath("$.data.tokenVersion").doesNotExist()
                );
    }

    // =========================================================
    // ADR 0001: RS256 tokens, JWKS, sessions, transition
    // =========================================================

    private String[] login(User user) throws Exception {
        String body = mockMvc.perform(
                        post("/api/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"email\":\"" + user.getEmail()
                                        + "\",\"password\":\"TestPassword123!\"}")
                )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        return new String[]{
                com.jayway.jsonpath.JsonPath.read(body, "$.data.accessToken"),
                com.jayway.jsonpath.JsonPath.read(body, "$.data.refreshToken")
        };
    }

    private java.security.PublicKey publicKeyFromJwks() throws Exception {
        String jwks = mockMvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("max-age")))
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].kid").isNotEmpty())
                .andExpect(jsonPath("$.keys[0].d").doesNotExist())
                .andReturn().getResponse().getContentAsString();

        return (java.security.PublicKey) io.jsonwebtoken.security.Jwks.setParser()
                .build()
                .parse(jwks)
                .getKeys()
                .iterator().next()
                .toKey();
    }

    @Test
    void jwksIsPublicAndVerifiesTokensIssuedByLogin() throws Exception {
        User user = createUser(RoleName.USER);
        String accessToken = login(user)[0];

        // Verified with the published public key only.
        var jws = Jwts.parser()
                .verifyWith(publicKeyFromJwks())
                .requireIssuer("careertrack-auth")
                .requireAudience("careertrack-api")
                .build()
                .parseSignedClaims(accessToken);

        org.junit.jupiter.api.Assertions.assertEquals("RS256", jws.getHeader().getAlgorithm());
        org.junit.jupiter.api.Assertions.assertEquals(
                user.getId().toString(), jws.getPayload().getSubject());
        org.junit.jupiter.api.Assertions.assertEquals(
                user.getUsername(), jws.getPayload().get("username", String.class));
        org.junit.jupiter.api.Assertions.assertNotNull(jws.getPayload().get("sid", String.class));
    }

    @Test
    void loginTokenWorksOnMe() throws Exception {
        User user = createUser(RoleName.USER);

        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(login(user)[0])))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.id").value(user.getId().toString()));
    }

    @Test
    void refreshKeepsTheSameSessionAndStoresIt() throws Exception {
        User user = createUser(RoleName.USER);
        String[] tokens = login(user);
        String sid = jwtService.extractAllClaims(tokens[0]).get("sid", String.class);

        String body = mockMvc.perform(
                        post("/api/auth/refresh")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"refreshToken\":\"" + tokens[1] + "\"}")
                )
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String newAccess = com.jayway.jsonpath.JsonPath.read(body, "$.data.accessToken");

        org.junit.jupiter.api.Assertions.assertEquals(
                sid, jwtService.extractAllClaims(newAccess).get("sid", String.class));

        Integer rowsInSession = jdbcTemplate.queryForObject(
                "select count(*) from refresh_tokens where session_id = ?::uuid",
                Integer.class, sid);
        org.junit.jupiter.api.Assertions.assertEquals(2, rowsInSession,
                "original and rotated refresh token share the session");
    }

    @Test
    void legacyHs256TokenStillWorksDuringTransition() throws Exception {
        User user = createUser(RoleName.USER);

        // Exactly what the previous Auth version issued.
        String legacy = Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getUsername())
                .claim("type", "ACCESS")
                .claim("tokenVersion", 0)
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900_000))
                .signWith(Keys.hmacShaKeyFor(
                        jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8)))
                .compact();

        mockMvc.perform(get("/api/auth/me").header("Authorization", bearer(legacy)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.username").value(user.getUsername()));
    }
}
