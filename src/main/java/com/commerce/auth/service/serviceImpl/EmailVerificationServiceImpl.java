package com.commerce.auth.service.serviceImpl;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 19:48
Version 1.0
*/

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.entity.EmailVerificationToken;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.BadRequestException;
import com.commerce.auth.repository.EmailVerificationTokenRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.service.EmailVerificationService;
import com.commerce.auth.utils.VerificationTokenUtils;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class EmailVerificationServiceImpl
        implements EmailVerificationService {

    private static final long TOKEN_EXPIRY_HOURS = 24;

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;

    @Override
    @Transactional
    public String createVerificationToken(User user) {

        // 1. Generate random token
        String rawToken =
                VerificationTokenUtils.generateToken();

        // 2. Hash token before persistence
        String tokenHash =
                VerificationTokenUtils.hashToken(rawToken);

        // 3. Build verification token entity
        EmailVerificationToken verificationToken =
                EmailVerificationToken.builder()
                        .user(user)
                        .tokenHash(tokenHash)
                        .expiredAt(
                                LocalDateTime.now(ZoneOffset.UTC)
                                        .plusHours(TOKEN_EXPIRY_HOURS)
                        )
                        .revoked(false)
                        .build();

        // 4. Persist only the token hash
        tokenRepository.save(verificationToken);

        // 5. Return raw token for internal delivery workflow
        return rawToken;
    }


    @Override
    @Transactional
    public void verifyEmail(String rawToken) {

        // 1. Validate raw token format
        if (rawToken == null ||
                !rawToken.matches("^[A-Za-z0-9_-]{43}$")) {

            throw new BadRequestException(
                    "Invalid or expired verification token"
            );
        }

        // 2. Hash token before database lookup
        String tokenHash =
                VerificationTokenUtils.hashToken(rawToken);

        // 3. Lock verification token row
        EmailVerificationToken verificationToken =
                tokenRepository.findByTokenHashForUpdate(tokenHash)
                        .orElseThrow(() ->
                                new BadRequestException(
                                        "Invalid or expired verification token"
                                )
                        );

        LocalDateTime now = LocalDateTime.now(ZoneOffset.UTC);

        // 4. Validate token state
        boolean invalidToken =
                Boolean.TRUE.equals(verificationToken.getRevoked())
                        || verificationToken.getUsedAt() != null
                        || !verificationToken.getExpiredAt().isAfter(now);

        if (invalidToken) {
            throw new BadRequestException(
                    "Invalid or expired verification token"
            );
        }

        // 5. Lock user to prevent concurrent account activation
        UUID userId = verificationToken.getUser().getId();

        User user = userRepository.findByIdForUpdate(userId)
                .orElseThrow(() ->
                        new BadRequestException(
                                "Invalid or expired verification token"
                        )
                );

        // 6. Only pending accounts can be activated
        if (user.getAccountStatus()
                != AccountStatus.PENDING_VERIFICATION) {

            throw new BadRequestException(
                    "Invalid or expired verification token"
            );
        }

        // 7. Activate account
        user.setEmailVerified(true);
        user.setEnabled(true);
        user.setAccountStatus(AccountStatus.ACTIVE);

        // 8. Mark verification token as consumed
        verificationToken.setUsedAt(now);

        // No explicit save required for managed JPA entities.
        // Changes are persisted during transaction commit.
    }

}
