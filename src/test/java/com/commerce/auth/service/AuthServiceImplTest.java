package com.commerce.auth.service;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 17:32
Version 1.0
*/

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.config.enums.RoleName;
import com.commerce.auth.dto.request.LogoutRequest;
import com.commerce.auth.dto.request.RefreshTokenRequest;
import com.commerce.auth.dto.request.RegisterRequest;
import com.commerce.auth.dto.response.RegisterResponse;
import com.commerce.auth.entity.RefreshToken;
import com.commerce.auth.entity.Role;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.BadRequestException;
import com.commerce.auth.exception.UnauthorizedException;
import com.commerce.auth.repository.RefreshTokenRepository;
import com.commerce.auth.repository.RoleRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.security.jwt.JwtService;
import com.commerce.auth.service.serviceImpl.AuthServiceImpl;
import com.commerce.auth.exception.ConflictException;

import com.commerce.auth.utils.TokenHasher;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    private static final String USERNAME = "dhito";
    private static final String EMAIL = "dhito@example.com";
    private static final String PASSWORD = "SecurePassword123!";
    private static final String HASHED_PASSWORD = "$2a$12$test-hash";
    private static final UUID USER_ID = UUID.randomUUID();

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private RefreshTokenService refreshTokenService;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private JwtService jwtService;

    @InjectMocks
    private AuthServiceImpl authService;

    private RegisterRequest validRequest;

    @BeforeEach
    void setUp() {
        validRequest = new RegisterRequest(
                USERNAME,
                EMAIL,
                PASSWORD
        );
    }

    // ==========================================================
    // HELPER METHODS
    // ==========================================================

    private void mockSuccessfulRegistration() {

        Role userRole = mock(Role.class);

        when(roleRepository.findByName(RoleName.USER))
                .thenReturn(Optional.of(userRole));

        when(passwordEncoder.encode(PASSWORD))
                .thenReturn(HASHED_PASSWORD);

        User savedUser = mock(User.class);

        when(savedUser.getId()).thenReturn(USER_ID);
        when(savedUser.getUsername()).thenReturn(USERNAME);
        when(savedUser.getEmail()).thenReturn(EMAIL);

        when(userRepository.save(any(User.class)))
                .thenReturn(savedUser);
    }

    private User captureSavedUser() {

        ArgumentCaptor<User> captor =
                ArgumentCaptor.forClass(User.class);

        verify(userRepository).save(captor.capture());

        return captor.getValue();
    }

    // ==========================================================
    // 1. SUCCESSFUL REGISTRATION
    // ==========================================================

    @Test
    void register_whenValid_shouldReturnUserInformation() {

        mockSuccessfulRegistration();

        RegisterResponse response =
                authService.register(validRequest);

        assertNotNull(response);
        assertEquals(USER_ID, response.id());
        assertEquals(USERNAME, response.username());
        assertEquals(EMAIL, response.email());

        verify(userRepository, times(1))
                .save(any(User.class));
    }

    // ==========================================================
    // 2. DEFAULT ROLE USER
    // ==========================================================

    @Test
    void register_whenValid_shouldAssignUserRole() {

        mockSuccessfulRegistration();

        authService.register(validRequest);

        User savedUser = captureSavedUser();

        Role assignedRole = roleRepository
                .findByName(RoleName.USER)
                .orElseThrow();

        assertEquals(1, savedUser.getRoles().size());
        assertTrue(savedUser.getRoles().contains(assignedRole));

        verify(roleRepository, times(2))
                .findByName(RoleName.USER);

        verify(roleRepository, never())
                .findByName(RoleName.ADMIN);
    }

    // ==========================================================
    // 3. PASSWORD ENCODING
    // ==========================================================

    @Test
    void register_whenValid_shouldEncodePassword() {

        mockSuccessfulRegistration();

        authService.register(validRequest);

        verify(passwordEncoder)
                .encode(PASSWORD);

        User savedUser = captureSavedUser();

        assertEquals(
                HASHED_PASSWORD,
                savedUser.getPassword()
        );
    }

    // ==========================================================
    // 4. PASSWORD MUST NOT BE PLAINTEXT
    // ==========================================================

    @Test
    void register_whenValid_shouldNotStorePlaintextPassword() {

        mockSuccessfulRegistration();

        authService.register(validRequest);

        User savedUser = captureSavedUser();

        assertNotEquals(
                PASSWORD,
                savedUser.getPassword()
        );
    }

    // ==========================================================
    // 5. TOKEN VERSION
    // ==========================================================

    @Test
    void register_whenValid_shouldInitializeTokenVersionZero() {

        mockSuccessfulRegistration();

        authService.register(validRequest);

        User savedUser = captureSavedUser();

        assertEquals(0, savedUser.getTokenVersion());
    }

    // ==========================================================
    // 6. ACCOUNT DISABLED BEFORE EMAIL VERIFICATION
    // ==========================================================

    @Test
    void register_whenValid_shouldInitializeEnabledFalse() {

        mockSuccessfulRegistration();

        authService.register(validRequest);

        User savedUser = captureSavedUser();

        assertEquals(Boolean.FALSE, savedUser.getEnabled());
    }

    // ==========================================================
    // 7. EMAIL NOT VERIFIED
    // ==========================================================

    @Test
    void register_whenValid_shouldInitializeEmailVerifiedFalse() {

        mockSuccessfulRegistration();

        authService.register(validRequest);

        User savedUser = captureSavedUser();

        assertEquals(
                Boolean.FALSE,
                savedUser.getEmailVerified()
        );
    }

    // ==========================================================
    // 8. DUPLICATE EMAIL
    // ==========================================================

    @Test
    void register_whenEmailAlreadyExists_shouldThrowConflictException() {

        when(userRepository.existsByEmail(EMAIL))
                .thenReturn(true);

        ConflictException exception = assertThrows(
                ConflictException.class,
                () -> authService.register(validRequest)
        );

        assertEquals(
                "Email already registered",
                exception.getMessage()
        );

        verify(userRepository, never())
                .save(any(User.class));

        verifyNoInteractions(
                roleRepository,
                passwordEncoder
        );
    }

    // ==========================================================
    // 9. DUPLICATE USERNAME
    // ==========================================================

    @Test
    void register_whenUsernameAlreadyExists_shouldThrowConflictException() {

        when(userRepository.existsByUsername(USERNAME))
                .thenReturn(true);

        ConflictException exception = assertThrows(
                ConflictException.class,
                () -> authService.register(validRequest)
        );

        assertEquals(
                "Username already registered",
                exception.getMessage()
        );

        verify(userRepository, never())
                .save(any(User.class));

        verifyNoInteractions(
                roleRepository,
                passwordEncoder
        );
    }

    // ==========================================================
    // 10. DEFAULT USER ROLE NOT CONFIGURED
    // ==========================================================

    @Test
    void register_whenUserRoleNotFound_shouldThrowException() {

        when(roleRepository.findByName(RoleName.USER))
                .thenReturn(Optional.empty());

        assertThrows(
                IllegalStateException.class,
                () -> authService.register(validRequest)
        );

        verify(userRepository, never())
                .save(any(User.class));
    }

    // ==========================================================
    // 11. PASSWORD ENCODER FAILURE
    // ==========================================================

    @Test
    void register_whenPasswordEncodingFails_shouldNotSaveUser() {

        when(passwordEncoder.encode(PASSWORD))
                .thenThrow(
                        new IllegalStateException("Encoder failure")
                );

        assertThrows(
                IllegalStateException.class,
                () -> authService.register(validRequest)
        );

        verify(userRepository, never())
                .save(any(User.class));
    }

    // ==========================================================
    // 12. DATABASE SAVE FAILURE
    // ==========================================================

    @Test
    void register_whenDatabaseSaveFails_shouldPropagateException() {

        Role userRole = mock(Role.class);

        when(roleRepository.findByName(RoleName.USER))
                .thenReturn(Optional.of(userRole));

        when(passwordEncoder.encode(PASSWORD))
                .thenReturn(HASHED_PASSWORD);

        when(userRepository.save(any(User.class)))
                .thenThrow(
                        new IllegalStateException("Database failure")
                );

        IllegalStateException exception = assertThrows(
                IllegalStateException.class,
                () -> authService.register(validRequest)
        );

        assertEquals(
                "Database failure",
                exception.getMessage()
        );

        verify(userRepository, times(1))
                .save(any(User.class));
    }

    @Test
    void register_whenEmailHasUppercase_shouldNormalizeBeforeSaving() {

        String rawEmail = "DHITO@EXAMPLE.COM";
        String normalizedEmail = "dhito@example.com";

        RegisterRequest request = new RegisterRequest(
                "dhito",
                rawEmail,
                "SecurePassword123!"
        );

        Role userRole = mock(Role.class);

        when(roleRepository.findByName(RoleName.USER))
                .thenReturn(Optional.of(userRole));

        when(passwordEncoder.encode(request.password()))
                .thenReturn("hashed-password");

        when(userRepository.save(any(User.class)))
                .thenAnswer(invocation -> {
                    User user = invocation.getArgument(0);
                    user.setId(UUID.randomUUID());
                    return user;
                });

        authService.register(request);

        verify(userRepository).existsByEmail(normalizedEmail);

        ArgumentCaptor<User> captor =
                ArgumentCaptor.forClass(User.class);

        verify(userRepository).save(captor.capture());

        assertEquals(
                normalizedEmail,
                captor.getValue().getEmail()
        );
    }

    @Test
    void register_whenValid_shouldInitializePendingVerificationStatus() {

        mockSuccessfulRegistration();

        authService.register(validRequest);

        User savedUser = captureSavedUser();

        assertEquals(
                AccountStatus.PENDING_VERIFICATION,
                savedUser.getAccountStatus()
        );

        assertEquals(Boolean.FALSE, savedUser.getEnabled());
        assertEquals(Boolean.FALSE, savedUser.getEmailVerified());
    }


    @ParameterizedTest
    @EnumSource(
            value = AccountStatus.class,
            names = {
                    "PENDING_VERIFICATION",
                    "SUSPENDED"
            }
    )
    void refreshToken_whenAccountIsNotActive_shouldReject(
            AccountStatus accountStatus
    ) {

        // Arrange
        String rawRefreshToken = "existing-refresh-token";

        User user = User.builder()
                .accountStatus(accountStatus)
                .enabled(false)
                .emailVerified(
                        accountStatus == AccountStatus.SUSPENDED
                )
                .build();

        RefreshToken storedToken = mock(RefreshToken.class);

        when(refreshTokenService.validate(rawRefreshToken))
                .thenReturn(storedToken);

        when(storedToken.getUser())
                .thenReturn(user);

        RefreshTokenRequest request =
                new RefreshTokenRequest(rawRefreshToken);

        MockHttpServletRequest httpRequest =
                new MockHttpServletRequest();

        // Act & Assert
        assertThrows(
                UnauthorizedException.class,
                () -> authService.refreshToken(
                        request,
                        httpRequest
                )
        );

        // JWT validation dan rotation tidak dilakukan
        verifyNoInteractions(jwtService);

        verify(refreshTokenService, never())
                .revoke(any());

        verify(refreshTokenService, never())
                .create(any(), anyString(), anyString(), anyString());
    }

    @Test
    void refreshToken_whenEnabledFalse_shouldReject()
            throws Exception {

        String rawRefreshToken = "existing-refresh-token";

        User user = User.builder()
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(false)
                .emailVerified(true)
                .build();

        RefreshToken storedToken = mock(RefreshToken.class);

        when(refreshTokenService.validate(rawRefreshToken))
                .thenReturn(storedToken);

        when(storedToken.getUser()).thenReturn(user);

        assertThrows(
                UnauthorizedException.class,
                () -> authService.refreshToken(
                        new RefreshTokenRequest(rawRefreshToken),
                        new MockHttpServletRequest()
                )
        );

        verifyNoInteractions(jwtService);

        verify(refreshTokenService, never()).revoke(any());
    }

    @Test
    void refreshToken_whenEmailNotVerified_shouldReject() {

        String rawRefreshToken = "existing-refresh-token";

        User user = User.builder()
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(false)
                .build();

        RefreshToken storedToken = mock(RefreshToken.class);

        when(refreshTokenService.validate(rawRefreshToken))
                .thenReturn(storedToken);

        when(storedToken.getUser()).thenReturn(user);

        assertThrows(
                UnauthorizedException.class,
                () -> authService.refreshToken(
                        new RefreshTokenRequest(rawRefreshToken),
                        new MockHttpServletRequest()
                )
        );

        verifyNoInteractions(jwtService);

        verify(refreshTokenService, never()).revoke(any());
    }


// 1. Malformed refresh JWT harus ditolak

    @Test
    void refreshToken_whenJwtMalformed_shouldThrowUnauthorized() {

        String rawToken = "malformed-refresh-token";

        User user = User.builder()
                .username("dhito")
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();

        RefreshToken storedToken = mock(RefreshToken.class);

        when(refreshTokenService.validate(rawToken))
                .thenReturn(storedToken);

        when(storedToken.getUser())
                .thenReturn(user);

        when(jwtService.isRefreshTokenValid(rawToken, user))
                .thenThrow(
                        new MalformedJwtException("Invalid JWT")
                );

        assertThrows(
                UnauthorizedException.class,
                () -> authService.refreshToken(
                        new RefreshTokenRequest(rawToken),
                        new MockHttpServletRequest()
                )
        );

        verify(refreshTokenService, never()).revoke(any());
        verify(refreshTokenService, never())
                .create(any(), anyString(), anyString(), anyString());
    }


// 2. Logout dengan token tidak ditemukan

    @Test
    void logout_whenRefreshTokenNotFound_shouldThrowUnauthorized() {

        String rawToken = "unknown-refresh-token";

        Authentication authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn("dhito");

        when(refreshTokenRepository.findByTokenHash(
                TokenHasher.sha256(rawToken)
        )).thenReturn(Optional.empty());

        assertThrows(
                UnauthorizedException.class,
                () -> authService.logout(
                        authentication,
                        new LogoutRequest(rawToken)
                )
        );

        verify(refreshTokenService, never()).revoke(any());
    }


// 3. Logout dengan token milik user lain

    @Test
    void logout_whenTokenBelongsToAnotherUser_shouldReject() {

        String rawToken = "another-user-refresh-token";

        Authentication authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn("dhito");

        User owner = User.builder()
                .username("otheruser")
                .build();

        RefreshToken storedToken = mock(RefreshToken.class);

        when(storedToken.getUser()).thenReturn(owner);

        when(refreshTokenRepository.findByTokenHash(
                TokenHasher.sha256(rawToken)
        )).thenReturn(Optional.of(storedToken));

        assertThrows(
                UnauthorizedException.class,
                () -> authService.logout(
                        authentication,
                        new LogoutRequest(rawToken)
                )
        );

        verify(refreshTokenService, never()).revoke(any());
    }


// 4. Logout dengan token valid

    @Test
    void logout_whenTokenBelongsToCurrentUser_shouldRevoke() {

        String rawToken = "valid-refresh-token";

        Authentication authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn("dhito");

        User owner = User.builder()
                .username("dhito")
                .build();

        RefreshToken storedToken = mock(RefreshToken.class);

        when(storedToken.getUser()).thenReturn(owner);

        when(refreshTokenRepository.findByTokenHash(
                TokenHasher.sha256(rawToken)
        )).thenReturn(Optional.of(storedToken));

        authService.logout(
                authentication,
                new LogoutRequest(rawToken)
        );

        verify(refreshTokenService).revoke(storedToken);
    }


    @Test
    void logoutAll_whenUserExists_shouldIncrementVersionAndRevokeTokens() {

        UUID userId = UUID.randomUUID();

        User user = User.builder()
                .id(userId)
                .username("dhito")
                .build();

        Authentication authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn("dhito");

        when(userRepository.findByUsername("dhito"))
                .thenReturn(Optional.of(user));

        when(userRepository.incrementTokenVersion(userId))
                .thenReturn(1);

        when(refreshTokenRepository.revokeAllActiveByUserId(userId))
                .thenReturn(3);

        authService.logoutAll(authentication);

        InOrder order = inOrder(
                userRepository,
                refreshTokenRepository
        );

        order.verify(userRepository).findByUsername("dhito");
        order.verify(userRepository).incrementTokenVersion(userId);
        order.verify(refreshTokenRepository)
                .revokeAllActiveByUserId(userId);
    }

    @Test
    void logoutAll_whenUserNotFound_shouldThrowUnauthorized() {

        Authentication authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn("unknown");

        when(userRepository.findByUsername("unknown"))
                .thenReturn(Optional.empty());

        assertThrows(
                UnauthorizedException.class,
                () -> authService.logoutAll(authentication)
        );

        verify(userRepository, never())
                .incrementTokenVersion(any());

        verifyNoInteractions(refreshTokenRepository);
    }

    @Test
    void logoutAll_whenVersionUpdateFails_shouldRollbackOperation() {

        UUID userId = UUID.randomUUID();

        User user = User.builder()
                .id(userId)
                .username("dhito")
                .build();

        Authentication authentication = mock(Authentication.class);

        when(authentication.getName()).thenReturn("dhito");

        when(userRepository.findByUsername("dhito"))
                .thenReturn(Optional.of(user));

        when(userRepository.incrementTokenVersion(userId))
                .thenReturn(0);

        assertThrows(
                IllegalStateException.class,
                () -> authService.logoutAll(authentication)
        );

        verify(refreshTokenRepository, never())
                .revokeAllActiveByUserId(any());
    }

}
