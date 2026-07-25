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

@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    private final JwtProperties jwtProperties;


    private SecretKey getSigningKey() {

        return Keys.hmacShaKeyFor(
                jwtProperties.getSecret()
                        .getBytes(StandardCharsets.UTF_8)
        );

    }


    @Override
    public String generateAccessToken(User user) {

        Date now = new Date();

        Date expired = new Date(
                now.getTime()
                        +
                        jwtProperties.getAccessTokenExpiration()
        );


        return Jwts.builder()

                // siapa usernya
                .subject(user.getUsername())


                // untuk revoke semua device
                .claim(
                        "tokenVersion",
                        user.getTokenVersion()
                )


                // membedakan token
                .claim(
                        "type",
                        "ACCESS"
                )


                .issuedAt(now)

                .expiration(expired)

                .signWith(getSigningKey())

                .compact();
    }



    @Override
    public String generateRefreshToken(User user) {

        Date now = new Date();

        Date expired = new Date(
                now.getTime()
                        +
                        jwtProperties.getRefreshTokenExpiration()
        );


        return Jwts.builder()

                .subject(user.getUsername())


                .claim(
                        "type",
                        "REFRESH"
                )


                .issuedAt(now)

                .expiration(expired)

                .signWith(getSigningKey())

                .compact();

    }



    @Override
    public String extractUsername(String token) {

        return extractAllClaims(token)
                .getSubject();

    }



    @Override
    public Claims extractAllClaims(String token) {

        return Jwts.parser()

                .verifyWith(getSigningKey())

                .build()

                .parseSignedClaims(token)

                .getPayload();

    }



    @Override
    public boolean isTokenValid(
            String token,
            User user
    ) {

        Claims claims =
                extractAllClaims(token);


        String username =
                claims.getSubject();


        String type =
                claims.get(
                        "type",
                        String.class
                );


        Integer tokenVersion =
                claims.get(
                        "tokenVersion",
                        Integer.class
                );


        return username.equals(user.getUsername())

                && "ACCESS".equals(type)

                && tokenVersion != null

                && tokenVersion.equals(
                user.getTokenVersion()
        )

                && !isTokenExpired(token);

    }



    private boolean isTokenExpired(String token) {

        return extractAllClaims(token)
                .getExpiration()
                .before(new Date());

    }

    @Override
    public boolean isRefreshTokenValid(
            String token,
            User user
    ) {

        Claims claims =
                extractAllClaims(token);


        String username =
                claims.getSubject();


        String type =
                claims.get(
                        "type",
                        String.class
                );


        return username.equals(user.getUsername())

                && "REFRESH".equals(type)

                && !isTokenExpired(token);

    }

}