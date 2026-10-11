package com.commerce.auth.integration;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 22:08
Version 1.0
*/

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.config.enums.RoleName;
import com.commerce.auth.entity.Role;
import com.commerce.auth.entity.User;
import com.commerce.auth.repository.RoleRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.security.jwt.JwtService;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Testcontainers
@Import(AuthorizationIntegrationTest.ProtectedTestController.class)
class AuthorizationIntegrationTest {

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
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // Endpoints available only during this integration test.
    @RestController
    public static class ProtectedTestController {

        @GetMapping("/api/career/_test/resource")
        public String careerResource() {
            return "CareerTrack resource";
        }

        @GetMapping("/api/admin/_test/resource")
        public String adminResource() {
            return "CMS resource";
        }

        @GetMapping("/api/admin/_test/audit")
        @PreAuthorize("hasAuthority('ADMIN_AUDIT_READ')")
        public String auditResource() {
            return "Audit resource";
        }

        @GetMapping("/api/admin/_test/role-assignment")
        @PreAuthorize("hasAuthority('ADMIN_ROLE_ASSIGN')")
        public String roleAssignmentResource() {
            return "Role assignment resource";
        }
    }

    private User createActiveUser(RoleName roleName) {

        String unique = UUID.randomUUID()
                .toString()
                .replace("-", "")
                .substring(0, 12);

        String username = "auth" + unique;

        Role role = roleRepository.findByName(roleName)
                .orElseThrow();

        User user = User.builder()
                .username(username)
                .email(username + "@example.com")
                .password(passwordEncoder.encode("SecurePassword123!"))
                .tokenVersion(0)
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();

        user.getRoles().add(role);

        return userRepository.saveAndFlush(user);
    }

    private String accessToken(User user) {
        return jwtService.generateAccessToken(user);
    }

    // 1. USER can access CareerTrack
    @Test
    void user_whenAccessingCareerTrack_shouldReturn200()
            throws Exception {

        User user = createActiveUser(RoleName.USER);

        mockMvc.perform(
                get("/api/career/_test/resource")
                        .header(
                                "Authorization",
                                "Bearer " + accessToken(user)
                        )
        ).andExpect(status().isOk());
    }

    // 2. USER cannot access CMS
    @Test
    void user_whenAccessingCms_shouldReturn403()
            throws Exception {

        User user = createActiveUser(RoleName.USER);

        mockMvc.perform(
                get("/api/admin/_test/resource")
                        .header(
                                "Authorization",
                                "Bearer " + accessToken(user)
                        )
        ).andExpect(status().isForbidden());
    }

    // 3. ADMIN can access CMS
    @Test
    void admin_whenAccessingCms_shouldReturn200()
            throws Exception {

        User admin = createActiveUser(RoleName.ADMIN);

        mockMvc.perform(
                get("/api/admin/_test/resource")
                        .header(
                                "Authorization",
                                "Bearer " + accessToken(admin)
                        )
        ).andExpect(status().isOk());
    }

    // 4. ADMIN cannot access CareerTrack
    @Test
    void admin_whenAccessingCareerTrack_shouldReturn403()
            throws Exception {

        User admin = createActiveUser(RoleName.ADMIN);

        mockMvc.perform(
                get("/api/career/_test/resource")
                        .header(
                                "Authorization",
                                "Bearer " + accessToken(admin)
                        )
        ).andExpect(status().isForbidden());
    }

    // 5. Unauthenticated requests are rejected
    @Test
    void request_withoutJwt_shouldReturn401()
            throws Exception {

        mockMvc.perform(
                get("/api/admin/_test/resource")
        ).andExpect(status().isUnauthorized());
    }

    // 6. Suspended ADMIN cannot use previous token
    @Test
    void suspendedAdmin_withOldJwt_shouldReturn401()
            throws Exception {

        User admin = createActiveUser(RoleName.ADMIN);

        String oldAccessToken = accessToken(admin);

        jdbcTemplate.update(
                """
                UPDATE users
                SET account_status = 'SUSPENDED',
                    enabled = FALSE
                WHERE id = ?
                """,
                admin.getId()
        );

        mockMvc.perform(
                get("/api/admin/_test/resource")
                        .header(
                                "Authorization",
                                "Bearer " + oldAccessToken
                        )
        ).andExpect(status().isUnauthorized());
    }

    // 7. ADMIN with audit permission is allowed
    @Test
    void admin_withAuditPermission_shouldReturn200()
            throws Exception {

        User admin = createActiveUser(RoleName.ADMIN);

        mockMvc.perform(
                get("/api/admin/_test/audit")
                        .header(
                                "Authorization",
                                "Bearer " + accessToken(admin)
                        )
        ).andExpect(status().isOk());
    }

    // 8. ADMIN cannot perform an ungranted operation
    @Test
    void admin_withoutRoleAssignPermission_shouldReturn403()
            throws Exception {

        User admin = createActiveUser(RoleName.ADMIN);

        mockMvc.perform(
                get("/api/admin/_test/role-assignment")
                        .header(
                                "Authorization",
                                "Bearer " + accessToken(admin)
                        )
        ).andExpect(status().isForbidden());
    }

    @Test
    void user_whenAssignedSecondRole_shouldBeRejectedByDatabase() {

        User user = createActiveUser(RoleName.USER);

        Role adminRole = roleRepository
                .findByName(RoleName.ADMIN)
                .orElseThrow();

        assertThrows(
                DataIntegrityViolationException.class,
                () -> jdbcTemplate.update(
                        """
                        INSERT INTO user_roles (user_id, role_id)
                        VALUES (?, ?)
                        """,
                        user.getId(),
                        adminRole.getId()
                )
        );
    }


}
