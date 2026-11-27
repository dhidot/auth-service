package com.commerce.auth.integration;

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.config.enums.RoleName;
import com.commerce.auth.entity.Role;
import com.commerce.auth.entity.User;
import com.commerce.auth.repository.RoleRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.security.jwt.JwtService;
import com.commerce.auth.service.TokenRevocationService;
import com.jayway.jsonpath.JsonPath;

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

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * ADR 0001, stage C2: logout and logout-all are recorded as revocations,
 * applied by Auth itself immediately and served to the gateway.
 */
@SpringBootTest(properties = {
        "careertrack.revocations.internal-api-key=" + RevocationIntegrationTest.KEY
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
class RevocationIntegrationTest {

    static final String KEY = "revocations-key-for-tests-0123456789abcdef";
    private static final String PASSWORD = "TestPassword123!";

    @Container
    @ServiceConnection
    static PostgreSQLContainer postgres =
            new PostgreSQLContainer("postgres:16-alpine")
                    .withDatabaseName("careertrack_test")
                    .withUsername("test")
                    .withPassword("test");

    @Autowired private MockMvc mockMvc;
    @Autowired private UserRepository userRepository;
    @Autowired private RoleRepository roleRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private JwtService jwtService;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private TokenRevocationService revocationService;

    private User createUser() {
        String suffix = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        Role role = roleRepository.findByName(RoleName.USER).orElseThrow();
        User user = User.builder()
                .username("rv" + suffix)
                .email("rv" + suffix + "@example.com")
                .password(passwordEncoder.encode(PASSWORD))
                .tokenVersion(0)
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();
        user.getRoles().add(role);
        return userRepository.saveAndFlush(user);
    }

    /** [accessToken, refreshToken] of a fresh login (a new session). */
    private String[] login(User user) throws Exception {
        String body = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"" + user.getEmail() + "\",\"password\":\"" + PASSWORD + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return new String[]{
                JsonPath.read(body, "$.data.accessToken"),
                JsonPath.read(body, "$.data.refreshToken")
        };
    }

    private String sid(String token) {
        return jwtService.extractSessionId(token).orElseThrow().toString();
    }

    private String snapshot() throws Exception {
        return mockMvc.perform(get("/internal/revocations").header("X-Internal-Api-Key", KEY))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    // -----------------------------------------------------------------
    // Logout of one session
    // -----------------------------------------------------------------

    @Test
    void logoutRevokesThatSessionImmediatelyButNotTheOthers() throws Exception {
        User user = createUser();
        String[] laptop = login(user);
        String[] phone = login(user);

        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + laptop[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + laptop[1] + "\"}"))
                .andExpect(status().isOk());

        // A copy of the laptop's access token no longer works, even on Auth.
        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + laptop[0]))
                .andExpect(status().isUnauthorized());

        // The phone's session is untouched.
        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + phone[0]))
                .andExpect(status().isOk());

        String body = snapshot();
        List<String> revokedSessions = JsonPath.read(body, "$.revocations[?(@.type=='SESSION')].sid");
        assertThat(revokedSessions).contains(sid(laptop[0])).doesNotContain(sid(phone[0]));
    }

    // -----------------------------------------------------------------
    // Logout of every session
    // -----------------------------------------------------------------

    @Test
    void logoutAllPublishesAUserRevocationCoveringExistingTokens() throws Exception {
        User user = createUser();
        String[] session = login(user);
        long issuedAt = jwtService.extractAllClaims(session[0]).getIssuedAt().toInstant().getEpochSecond();

        mockMvc.perform(post("/api/auth/logout-all").header("Authorization", "Bearer " + session[0]))
                .andExpect(status().isOk());

        String body = snapshot();
        List<Number> notBefore = JsonPath.read(body,
                "$.revocations[?(@.type=='USER' && @.sub=='" + user.getId() + "')].notBefore");
        assertThat(notBefore).hasSize(1);
        // The gateway rule is "iat < notBefore => revoked".
        assertThat(issuedAt).isLessThan(notBefore.getFirst().longValue());
    }

    // -----------------------------------------------------------------
    // Internal endpoint
    // -----------------------------------------------------------------

    @Test
    void internalEndpointRequiresTheKey() throws Exception {
        mockMvc.perform(get("/internal/revocations"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/internal/revocations").header("X-Internal-Api-Key", "wrong-key"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/internal/revocations").header("X-Internal-Api-Key", KEY + "x"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void internalEndpointServesTheContractWithoutCaching() throws Exception {
        User user = createUser();
        String[] session = login(user);
        mockMvc.perform(post("/api/auth/logout")
                        .header("Authorization", "Bearer " + session[0])
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"refreshToken\":\"" + session[1] + "\"}"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/internal/revocations").header("X-Internal-Api-Key", KEY))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(jsonPath("$.serverTime").isNumber())
                .andExpect(jsonPath("$.revocations[?(@.sid=='" + sid(session[0]) + "')].type").value("SESSION"))
                .andExpect(jsonPath("$.revocations[?(@.sid=='" + sid(session[0]) + "')].sub").value(user.getId().toString()))
                .andExpect(jsonPath("$.revocations[?(@.sid=='" + sid(session[0]) + "')].expiresAt").isNotEmpty());
    }

    @Test
    void onlyActiveEntriesAreServedAndExpiredOnesArePurged() throws Exception {
        User user = createUser();
        UUID expiredSid = UUID.randomUUID();
        UUID activeSid = UUID.randomUUID();

        jdbcTemplate.update("""
                insert into token_revocations (revocation_type, user_id, session_id, created_at, expires_at)
                values ('SESSION', ?, ?, now() - interval '20 minutes', now() - interval '1 minute')
                """, user.getId(), expiredSid);
        jdbcTemplate.update("""
                insert into token_revocations (revocation_type, user_id, session_id, created_at, expires_at)
                values ('SESSION', ?, ?, now(), now() + interval '15 minutes')
                """, user.getId(), activeSid);

        String body = snapshot();
        assertThat(body).contains(activeSid.toString()).doesNotContain(expiredSid.toString());

        revocationService.purgeExpired();

        Integer expiredLeft = jdbcTemplate.queryForObject(
                "select count(*) from token_revocations where session_id = ?", Integer.class, expiredSid);
        Integer activeLeft = jdbcTemplate.queryForObject(
                "select count(*) from token_revocations where session_id = ?", Integer.class, activeSid);
        assertThat(expiredLeft).isZero();
        assertThat(activeLeft).isEqualTo(1);
    }

    @Test
    void databaseRejectsInconsistentEntries() {
        User user = createUser();

        org.junit.jupiter.api.Assertions.assertThrows(Exception.class, () -> jdbcTemplate.update("""
                insert into token_revocations (revocation_type, user_id, expires_at)
                values ('SESSION', ?, now() + interval '1 minute')
                """, user.getId()));
        org.junit.jupiter.api.Assertions.assertThrows(Exception.class, () -> jdbcTemplate.update("""
                insert into token_revocations (revocation_type, user_id, expires_at)
                values ('USER', ?, now() + interval '1 minute')
                """, user.getId()));
    }
}
