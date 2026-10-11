package com.commerce.auth.service.serviceImpl;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:40
Version 1.0
*/

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.entity.RefreshToken;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.UnauthorizedException;
import com.commerce.auth.repository.RefreshTokenRepository;
import com.commerce.auth.service.RefreshTokenService;
import com.commerce.auth.utils.TokenHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final JwtProperties jwtProperties;



    @Override
    public RefreshToken create(
            User user,
            String refreshToken,
            String deviceInfo,
            String ipAddress
    ) {

        RefreshToken entity = RefreshToken.builder()
                .user(user)
                .tokenHash(TokenHasher.sha256(refreshToken))
                .expiredAt(
                        LocalDateTime.now().plusSeconds(
                                jwtProperties.getRefreshTokenExpiration()
                                        / 1000
                        )
                )
                .revoked(false)
                .deviceInfo(deviceInfo)
                .ipAddress(ipAddress)
                .build();

        return repository.save(entity);
    }

    @Override
    @Transactional(propagation = Propagation.MANDATORY)
    public RefreshToken validate(String refreshToken) {

        String tokenHash =
                TokenHasher.sha256(refreshToken);

        // Lock database row until outer transaction finishes
        RefreshToken token = repository
                .findByTokenHashForUpdate(tokenHash)
                .orElseThrow(() ->
                        new UnauthorizedException(
                                "Invalid refresh token"
                        )
                );

        // Reject revoked token
        if (Boolean.TRUE.equals(token.getRevoked())) {
            throw new UnauthorizedException(
                    "Invalid refresh token"
            );
        }

        // Reject expired token, including exact expiration boundary
        LocalDateTime now = LocalDateTime.now();

        if (!token.getExpiredAt().isAfter(now)) {
            throw new UnauthorizedException(
                    "Invalid refresh token"
            );
        }

        return token;
    }

    @Override
    public void revoke(RefreshToken refreshToken) {

        refreshToken.setRevoked(true);

        repository.save(refreshToken);

    }
}