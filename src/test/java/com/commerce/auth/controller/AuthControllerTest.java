package com.commerce.auth.controller;

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.dto.request.RegisterRequest;
import com.commerce.auth.dto.response.RegisterResponse;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.BadRequestException;
import com.commerce.auth.security.CustomUserDetailsService;
import com.commerce.auth.security.SecurityConfig;
import com.commerce.auth.security.UserPrincipal;
import com.commerce.auth.security.jwt.JwtService;
import com.commerce.auth.service.AuthService;

import com.commerce.auth.service.EmailVerificationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@Import(SecurityConfig.class)
@TestPropertySource(properties = {
        "spring.jackson.deserialization.fail-on-unknown-properties=true"
})
class AuthControllerTest {

    private static final String REGISTER_URL = "/api/auth/register";

    private static final String VALID_USERNAME = "dhito";
    private static final String VALID_EMAIL = "dhito@example.com";
    private static final String VALID_PASSWORD = "SecurePassword123!";

    private static final String VERIFY_EMAIL_URL =
            "/api/auth/verify-email";

    private static final String VALID_VERIFICATION_TOKEN =
            "A".repeat(43);

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AuthService authService;

    @MockitoBean
    private JwtService jwtService;

    @MockitoBean
    private CustomUserDetailsService customUserDetailsService;

    @MockitoBean
    private EmailVerificationService emailVerificationService;

    // ==========================================================
    // HELPER METHODS
    // ==========================================================

    private String registerJson(
            String username,
            String email,
            String password
    ) {
        return """
                {
                    "username": "%s",
                    "email": "%s",
                    "password": "%s"
                }
                """.formatted(username, email, password);
    }

    private ResultActions performRegister(String json)
            throws Exception {

        return mockMvc.perform(
                post(REGISTER_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json)
        );
    }

    private void assertBadRequest(String json)
            throws Exception {

        performRegister(json)
                .andExpect(status().isBadRequest());

        verifyNoInteractions(authService);
    }

    // ==========================================================
    // 1. SUCCESS CASE
    // ==========================================================

    @Test
    void register_whenRequestIsValid_shouldReturn201()
            throws Exception {

        RegisterResponse response = new RegisterResponse(
                UUID.randomUUID(),
                VALID_USERNAME,
                VALID_EMAIL
        );

        when(authService.register(any(RegisterRequest.class)))
                .thenReturn(response);

        String request = registerJson(
                VALID_USERNAME,
                VALID_EMAIL,
                VALID_PASSWORD
        );

        performRegister(request)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").value("201"))
                .andExpect(jsonPath("$.data.username")
                        .value(VALID_USERNAME))
                .andExpect(jsonPath("$.data.email")
                        .value(VALID_EMAIL))
                .andExpect(jsonPath("$.data.password")
                        .doesNotExist());

        verify(authService)
                .register(any(RegisterRequest.class));
    }

    // ==========================================================
    // 2. USERNAME BLANK
    // ==========================================================

    @Test
    void register_whenUsernameIsBlank_shouldReturn400()
            throws Exception {

        String request = registerJson(
                "",
                VALID_EMAIL,
                VALID_PASSWORD
        );

        assertBadRequest(request);
    }

    // ==========================================================
    // 3. USERNAME TOO SHORT
    // ==========================================================

    @Test
    void register_whenUsernameTooShort_shouldReturn400()
            throws Exception {

        String request = registerJson(
                "ab",
                VALID_EMAIL,
                VALID_PASSWORD
        );

        assertBadRequest(request);
    }

    // ==========================================================
    // 4. USERNAME TOO LONG
    // ==========================================================

    @Test
    void register_whenUsernameTooLong_shouldReturn400()
            throws Exception {

        String request = registerJson(
                "a".repeat(51),
                VALID_EMAIL,
                VALID_PASSWORD
        );

        assertBadRequest(request);
    }

    // ==========================================================
    // 5. EMAIL BLANK
    // ==========================================================

    @Test
    void register_whenEmailIsBlank_shouldReturn400()
            throws Exception {

        String request = registerJson(
                VALID_USERNAME,
                "",
                VALID_PASSWORD
        );

        assertBadRequest(request);
    }

    // ==========================================================
    // 6. EMAIL INVALID
    // ==========================================================

    @Test
    void register_whenEmailIsInvalid_shouldReturn400()
            throws Exception {

        String request = registerJson(
                VALID_USERNAME,
                "invalid-email",
                VALID_PASSWORD
        );

        assertBadRequest(request);
    }

    // ==========================================================
    // 7. PASSWORD BLANK
    // ==========================================================

    @Test
    void register_whenPasswordIsBlank_shouldReturn400()
            throws Exception {

        String request = registerJson(
                VALID_USERNAME,
                VALID_EMAIL,
                ""
        );

        assertBadRequest(request);
    }

    // ==========================================================
    // 8. PASSWORD TOO SHORT
    // ==========================================================

    @Test
    void register_whenPasswordTooShort_shouldReturn400()
            throws Exception {

        String request = registerJson(
                VALID_USERNAME,
                VALID_EMAIL,
                "12345"
        );

        assertBadRequest(request);
    }

    // ==========================================================
    // 9. PASSWORD TOO LONG
    // ==========================================================

    @Test
    void register_whenPasswordTooLong_shouldReturn400()
            throws Exception {

        String request = registerJson(
                VALID_USERNAME,
                VALID_EMAIL,
                "A".repeat(129)
        );

        assertBadRequest(request);
    }

    // ==========================================================
    // 10. MALFORMED JSON
    // ==========================================================

    @Test
    void register_whenJsonIsMalformed_shouldReturn400()
            throws Exception {

        String request = """
                {
                    "username": "dhito",
                    "email": "dhito@example.com",
                    "password":
                }
                """;

        assertBadRequest(request);
    }

    // ==========================================================
    // 11. ROLE ADMIN INJECTION
    // ==========================================================

    @Test
    void register_whenRoleAdminIsProvided_shouldReturn400()
            throws Exception {

        String request = """
                {
                    "username": "dhito",
                    "email": "dhito@example.com",
                    "password": "SecurePassword123!",
                    "role": "ADMIN"
                }
                """;

        assertBadRequest(request);
    }

    // ==========================================================
    // 12. ROLE SUPER_ADMIN INJECTION
    // ==========================================================

    @Test
    void register_whenRoleSuperAdminIsProvided_shouldReturn400()
            throws Exception {

        String request = """
                {
                    "username": "dhito",
                    "email": "dhito@example.com",
                    "password": "SecurePassword123!",
                    "role": "SUPER_ADMIN"
                }
                """;

        assertBadRequest(request);
    }

    // 1. Valid verification token
    @Test
    void verifyEmail_whenTokenIsValid_shouldReturn200()
            throws Exception {

        String request = """
            {
                "token": "%s"
            }
            """.formatted(VALID_VERIFICATION_TOKEN);

        mockMvc.perform(
                        post(VERIFY_EMAIL_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("200"))
                .andExpect(jsonPath("$.message")
                        .value("Email verified successfully"));

        verify(emailVerificationService)
                .verifyEmail(VALID_VERIFICATION_TOKEN);
    }

    // 2. Empty token
    @Test
    void verifyEmail_whenTokenIsBlank_shouldReturn400()
            throws Exception {

        mockMvc.perform(
                        post(VERIFY_EMAIL_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                            {"token": ""}
                            """)
                )
                .andExpect(status().isBadRequest());

        verifyNoInteractions(emailVerificationService);
    }

    // 3. Missing token
    @Test
    void verifyEmail_whenTokenIsMissing_shouldReturn400()
            throws Exception {

        mockMvc.perform(
                        post(VERIFY_EMAIL_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{}")
                )
                .andExpect(status().isBadRequest());

        verifyNoInteractions(emailVerificationService);
    }

    // 4. Invalid token format
    @Test
    void verifyEmail_whenTokenFormatIsInvalid_shouldReturn400()
            throws Exception {

        mockMvc.perform(
                        post(VERIFY_EMAIL_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("""
                            {"token": "invalid-token"}
                            """)
                )
                .andExpect(status().isBadRequest());

        verifyNoInteractions(emailVerificationService);
    }

    // 5. Service rejects the verification token
    @Test
    void verifyEmail_whenServiceRejectsToken_shouldReturn400()
            throws Exception {

        doThrow(new BadRequestException(
                "Invalid or expired verification token"
        ))
                .when(emailVerificationService)
                .verifyEmail(VALID_VERIFICATION_TOKEN);

        String request = """
            {
                "token": "%s"
            }
            """.formatted(VALID_VERIFICATION_TOKEN);

        mockMvc.perform(
                        post(VERIFY_EMAIL_URL)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(request)
                )
                .andExpect(status().isBadRequest());

        verify(emailVerificationService)
                .verifyEmail(VALID_VERIFICATION_TOKEN);
    }


    @Test
    void logoutAll_whenAuthenticated_shouldReturn200()
            throws Exception {

        String accessToken = "test-logout-all-access-token";

        User user = User.builder()
                .username("dhito")
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();

        UserPrincipal principal = new UserPrincipal(user);

        when(jwtService.extractUsername(accessToken))
                .thenReturn("dhito");

        when(customUserDetailsService.loadUserByUsername("dhito"))
                .thenReturn(principal);

        when(jwtService.isTokenValid(accessToken, user))
                .thenReturn(true);

        mockMvc.perform(
                        post("/api/auth/logout-all")
                                .header(
                                        "Authorization",
                                        "Bearer " + accessToken
                                )
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("200"))
                .andExpect(jsonPath("$.message")
                        .value("All sessions revoked successfully"));

        verify(authService).logoutAll(
                argThat(authentication ->
                        authentication != null
                                && "dhito".equals(authentication.getName())
                )
        );
    }

    @Test
    void logoutAll_whenUnauthenticated_shouldReturn401()
            throws Exception {

        mockMvc.perform(
                        post("/api/auth/logout-all")
                )
                .andExpect(status().isUnauthorized());

        verify(authService, never()).logoutAll(any());
    }
}