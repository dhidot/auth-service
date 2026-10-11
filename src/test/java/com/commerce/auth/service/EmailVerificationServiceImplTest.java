package com.commerce.auth.service;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 19:49
Version 1.0
*/

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.entity.EmailVerificationToken;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.BadRequestException;
import com.commerce.auth.repository.EmailVerificationTokenRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.service.serviceImpl.EmailVerificationServiceImpl;
import com.commerce.auth.utils.VerificationTokenUtils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class EmailVerificationServiceImplTest {

    @Mock
    private EmailVerificationTokenRepository tokenRepository;

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private EmailVerificationServiceImpl verificationService;


    private static final String VALID_TOKEN = "A".repeat(43);

    private User pendingUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .username("dhito")
                .email("dhito@example.com")
                .enabled(false)
                .emailVerified(false)
                .accountStatus(AccountStatus.PENDING_VERIFICATION)
                .build();
    }

    private EmailVerificationToken validVerificationToken(User user) {
        return EmailVerificationToken.builder()
                .id(UUID.randomUUID())
                .user(user)
                .tokenHash(VerificationTokenUtils.hashToken(VALID_TOKEN))
                .expiredAt(LocalDateTime.now(ZoneOffset.UTC).plusHours(1))
                .usedAt(null)
                .revoked(false)
                .build();
    }

    private void mockExistingToken(EmailVerificationToken token) {
        when(tokenRepository.findByTokenHashForUpdate(
                VerificationTokenUtils.hashToken(VALID_TOKEN)
        )).thenReturn(Optional.of(token));
    }


    private User testUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .username("dhito")
                .email("dhito@example.com")
                .build();
    }

    @Test
    void createVerificationToken_shouldSaveHashedToken() {

        String rawToken =
                verificationService.createVerificationToken(testUser());

        ArgumentCaptor<EmailVerificationToken> captor =
                ArgumentCaptor.forClass(EmailVerificationToken.class);

        verify(tokenRepository).save(captor.capture());

        EmailVerificationToken saved = captor.getValue();

        assertEquals(
                VerificationTokenUtils.hashToken(rawToken),
                saved.getTokenHash()
        );

        assertNotEquals(rawToken, saved.getTokenHash());
    }

    @Test
    void createVerificationToken_shouldAssociateCorrectUser() {

        User user = testUser();

        verificationService.createVerificationToken(user);

        ArgumentCaptor<EmailVerificationToken> captor =
                ArgumentCaptor.forClass(EmailVerificationToken.class);

        verify(tokenRepository).save(captor.capture());

        assertSame(user, captor.getValue().getUser());
    }

    @Test
    void createVerificationToken_shouldExpireAfter24Hours() {

        LocalDateTime before =
                LocalDateTime.now(ZoneOffset.UTC).plusHours(24);

        verificationService.createVerificationToken(testUser());

        LocalDateTime after =
                LocalDateTime.now(ZoneOffset.UTC).plusHours(24);

        ArgumentCaptor<EmailVerificationToken> captor =
                ArgumentCaptor.forClass(EmailVerificationToken.class);

        verify(tokenRepository).save(captor.capture());

        LocalDateTime expiry =
                captor.getValue().getExpiredAt();

        assertFalse(expiry.isBefore(before));
        assertFalse(expiry.isAfter(after));
    }

    @Test
    void createVerificationToken_shouldInitializeUnusedAndNotRevoked() {

        verificationService.createVerificationToken(testUser());

        ArgumentCaptor<EmailVerificationToken> captor =
                ArgumentCaptor.forClass(EmailVerificationToken.class);

        verify(tokenRepository).save(captor.capture());

        EmailVerificationToken saved = captor.getValue();

        assertNull(saved.getUsedAt());
        assertEquals(Boolean.FALSE, saved.getRevoked());
    }


// ==========================================================
// 1. VALID TOKEN
// ==========================================================

    @Test
    void verifyEmail_whenTokenIsValid_shouldActivateUser() {

        User user = pendingUser();
        EmailVerificationToken token = validVerificationToken(user);

        mockExistingToken(token);

        when(userRepository.findByIdForUpdate(user.getId()))
                .thenReturn(Optional.of(user));

        verificationService.verifyEmail(VALID_TOKEN);

        assertEquals(AccountStatus.ACTIVE, user.getAccountStatus());
        assertTrue(user.getEnabled());
        assertTrue(user.getEmailVerified());

        assertNotNull(token.getUsedAt());

        verify(tokenRepository).findByTokenHashForUpdate(
                VerificationTokenUtils.hashToken(VALID_TOKEN)
        );
        verify(userRepository).findByIdForUpdate(user.getId());
    }

// ==========================================================
// 2. TOKEN NOT FOUND
// ==========================================================

    @Test
    void verifyEmail_whenTokenNotFound_shouldThrowBadRequest() {

        when(tokenRepository.findByTokenHashForUpdate(
                VerificationTokenUtils.hashToken(VALID_TOKEN)
        )).thenReturn(Optional.empty());

        assertThrows(
                BadRequestException.class,
                () -> verificationService.verifyEmail(VALID_TOKEN)
        );

        verifyNoInteractions(userRepository);
    }

// ==========================================================
// 3. EXPIRED TOKEN
// ==========================================================

    @Test
    void verifyEmail_whenTokenExpired_shouldRejectVerification() {

        User user = pendingUser();
        EmailVerificationToken token = validVerificationToken(user);

        token.setExpiredAt(
                LocalDateTime.now(ZoneOffset.UTC).minusMinutes(1)
        );

        mockExistingToken(token);

        assertThrows(
                BadRequestException.class,
                () -> verificationService.verifyEmail(VALID_TOKEN)
        );

        assertEquals(
                AccountStatus.PENDING_VERIFICATION,
                user.getAccountStatus()
        );
        assertNull(token.getUsedAt());

        verifyNoInteractions(userRepository);
    }

// ==========================================================
// 4. REVOKED TOKEN
// ==========================================================

    @Test
    void verifyEmail_whenTokenRevoked_shouldRejectVerification() {

        User user = pendingUser();
        EmailVerificationToken token = validVerificationToken(user);

        token.setRevoked(true);

        mockExistingToken(token);

        assertThrows(
                BadRequestException.class,
                () -> verificationService.verifyEmail(VALID_TOKEN)
        );

        assertFalse(user.getEnabled());
        assertNull(token.getUsedAt());

        verifyNoInteractions(userRepository);
    }

// ==========================================================
// 5. ALREADY USED TOKEN
// ==========================================================

    @Test
    void verifyEmail_whenTokenAlreadyUsed_shouldRejectVerification() {

        User user = pendingUser();
        EmailVerificationToken token = validVerificationToken(user);

        LocalDateTime previousUsedAt =
                LocalDateTime.now(ZoneOffset.UTC).minusMinutes(5);

        token.setUsedAt(previousUsedAt);

        mockExistingToken(token);

        assertThrows(
                BadRequestException.class,
                () -> verificationService.verifyEmail(VALID_TOKEN)
        );

        assertEquals(previousUsedAt, token.getUsedAt());
        assertFalse(user.getEmailVerified());

        verifyNoInteractions(userRepository);
    }

// ==========================================================
// 6. SUSPENDED ACCOUNT
// ==========================================================

    @Test
    void verifyEmail_whenUserSuspended_shouldNotActivateAccount() {

        User user = pendingUser();
        user.setAccountStatus(AccountStatus.SUSPENDED);

        EmailVerificationToken token = validVerificationToken(user);

        mockExistingToken(token);

        when(userRepository.findByIdForUpdate(user.getId()))
                .thenReturn(Optional.of(user));

        assertThrows(
                BadRequestException.class,
                () -> verificationService.verifyEmail(VALID_TOKEN)
        );

        assertEquals(AccountStatus.SUSPENDED, user.getAccountStatus());
        assertFalse(user.getEnabled());
        assertNull(token.getUsedAt());
    }

// ==========================================================
// 7. ACCOUNT ALREADY ACTIVE
// ==========================================================

    @Test
    void verifyEmail_whenUserAlreadyActive_shouldRejectVerification() {

        User user = pendingUser();

        user.setAccountStatus(AccountStatus.ACTIVE);
        user.setEnabled(true);
        user.setEmailVerified(true);

        EmailVerificationToken token = validVerificationToken(user);

        mockExistingToken(token);

        when(userRepository.findByIdForUpdate(user.getId()))
                .thenReturn(Optional.of(user));

        assertThrows(
                BadRequestException.class,
                () -> verificationService.verifyEmail(VALID_TOKEN)
        );

        assertEquals(AccountStatus.ACTIVE, user.getAccountStatus());
        assertTrue(user.getEmailVerified());
        assertNull(token.getUsedAt());
    }

// ==========================================================
// 8. INVALID TOKEN FORMAT
// ==========================================================

    @Test
    void verifyEmail_whenTokenFormatInvalid_shouldNotQueryDatabase() {

        assertThrows(
                BadRequestException.class,
                () -> verificationService.verifyEmail("invalid-token")
        );

        verifyNoInteractions(tokenRepository, userRepository);
    }

}
