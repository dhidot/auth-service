package com.commerce.auth.service.serviceImpl;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 22:03
Version 1.0
*/

import com.commerce.auth.entity.EmailVerificationToken;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.BadRequestException;
import com.commerce.auth.repository.EmailVerificationTokenRepository;
import com.commerce.auth.service.EmailVerificationTokenService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Transactional
public class EmailVerificationTokenServiceImpl
        implements EmailVerificationTokenService {

    private final EmailVerificationTokenRepository repository;
    @Override
    @Transactional
    public EmailVerificationToken create(User user) {

        repository.revokeActiveTokens(user.getId());

        EmailVerificationToken token =
                EmailVerificationToken.builder()
                        .user(user)
                        .token(UUID.randomUUID())
                        .expiredAt(LocalDateTime.now().plusHours(24))
                        .build();

        return repository.save(token);
    }

    @Override
    public void verify(UUID token) {

        EmailVerificationToken verificationToken =
                repository.findByToken(token)
                        .orElseThrow(() ->
                                new BadRequestException("Invalid verification token"));

        if (verificationToken.getRevoked()) {
            throw new BadRequestException("Verification token is no longer valid");
        }

        if (verificationToken.isUsed()) {
            throw new BadRequestException(
                    "Verification token already used");
        }

        if (verificationToken.isExpired()) {
            throw new BadRequestException(
                    "Verification token expired");
        }

        User user = verificationToken.getUser();

        user.setEnabled(true);
        user.setEmailVerified(true);

        verificationToken.setUsedAt(LocalDateTime.now());
    }

    @Override
    public void resend(User user) {

    }

}
