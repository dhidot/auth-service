package com.commerce.auth.security.jwt;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 27/11/2026
Version 2.0
*/

import com.commerce.auth.entity.User;
import io.jsonwebtoken.Claims;

import java.util.UUID;

public interface JwtService {

    /** Access token for an existing session ({@code sid}). */
    String generateAccessToken(User user, UUID sessionId);

    /** Refresh token for an existing session ({@code sid}). */
    String generateRefreshToken(User user, UUID sessionId);

    /** Access token for a new, standalone session. Mainly for tests. */
    default String generateAccessToken(User user) {
        return generateAccessToken(user, UUID.randomUUID());
    }

    /** Refresh token for a new, standalone session. Mainly for tests. */
    default String generateRefreshToken(User user) {
        return generateRefreshToken(user, UUID.randomUUID());
    }

    /**
     * The verified {@code sub}: a user UUID for current tokens, or a
     * username for legacy HS256 tokens during the transition.
     */
    String extractSubject(String token);

    /** Verified claims; throws {@link io.jsonwebtoken.JwtException} if invalid. */
    Claims extractAllClaims(String token);

    boolean isTokenValid(
            String token,
            User user
    );

    boolean isRefreshTokenValid(
            String token,
            User user
    );

}
