package com.commerce.auth.security.jwt;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:55
Version 1.0
*/

import com.commerce.auth.entity.User;
import io.jsonwebtoken.Claims;

public interface JwtService {

    String generateAccessToken(User user);

    String generateRefreshToken(User user);

    String extractUsername(String token);

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