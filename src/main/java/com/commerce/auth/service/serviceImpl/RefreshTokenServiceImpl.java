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
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final JwtProperties jwtProperties;


    @Override
    public RefreshToken create(User user, String refreshToken, String deviceInfo, String ipAddress) {

        RefreshToken entity =
                RefreshToken.builder()
                        .user(user)
                        .tokenHash(TokenHasher.sha256(refreshToken))
                        .expiredAt(LocalDateTime.now().plusSeconds(
                                jwtProperties.getRefreshTokenExpiration() / 1000
                        ))
                        .revoked(false)
                        .build();

        return repository.save(entity);

    }

    @Override
    public RefreshToken validate(String refreshToken) {

        String hash = TokenHasher.sha256(refreshToken);

        RefreshToken token =
                repository.findByTokenHash(hash)
                        .orElseThrow(() ->
                                new UnauthorizedException("Refresh token not found"));

        if (Boolean.TRUE.equals(token.getRevoked())) {
            throw new UnauthorizedException("Refresh token revoked");
        }

        if (token.getExpiredAt().isBefore(LocalDateTime.now())) {
            throw new UnauthorizedException("Refresh token expired");
        }

        return token;
    }

    @Override
    public void revoke(RefreshToken refreshToken) {

        refreshToken.setRevoked(true);

        repository.save(refreshToken);

    }
}