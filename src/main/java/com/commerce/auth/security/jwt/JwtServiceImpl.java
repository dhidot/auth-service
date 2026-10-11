package com.commerce.auth.security.jwt;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:09
Version 1.0
*/

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private static final String ACCESS = "ACCESS";
    private static final String REFRESH = "REFRESH";

    private final JwtProperties jwtProperties;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(
                jwtProperties.getSecret()
                        .getBytes(StandardCharsets.UTF_8)
        );
    }

    private String generateToken(
            User user,
            String type,
            long expirationMillis
    ) {

        Date now = new Date();

        Date expiration = new Date(
                now.getTime() + expirationMillis
        );

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getUsername())
                .claim("type", type)
                .claim("tokenVersion", user.getTokenVersion())
                .issuedAt(now)
                .expiration(expiration)
                .signWith(getSigningKey())
                .compact();
    }

    @Override
    public String generateAccessToken(User user) {
        return generateToken(
                user,
                ACCESS,
                jwtProperties.getAccessTokenExpiration()
        );
    }

    @Override
    public String generateRefreshToken(User user) {
        return generateToken(
                user,
                REFRESH,
                jwtProperties.getRefreshTokenExpiration()
        );
    }

    @Override
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    @Override
    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean hasValidCommonClaims(
            Claims claims,
            User user
    ) {

        if (user == null || !user.isAccountActive()) {
            return false;
        }

        Integer tokenVersion =
                claims.get("tokenVersion", Integer.class);

        return Objects.equals(
                claims.getSubject(),
                user.getUsername()
        )
                && tokenVersion != null
                && tokenVersion.equals(user.getTokenVersion())
                && claims.getExpiration() != null
                && claims.getId() != null
                && !claims.getId().isBlank();
    }

    @Override
    public boolean isTokenValid(
            String token,
            User user
    ) {

        Claims claims = extractAllClaims(token);

        return ACCESS.equals(
                claims.get("type", String.class)
        )
                && hasValidCommonClaims(claims, user);
    }

    @Override
    public boolean isRefreshTokenValid(
            String token,
            User user
    ) {

        Claims claims = extractAllClaims(token);

        return REFRESH.equals(
                claims.get("type", String.class)
        )
                && hasValidCommonClaims(claims, user);
    }
}
