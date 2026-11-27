package com.commerce.auth.config;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 26/11/2026
Version 1.1
*/

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.nio.charset.StandardCharsets;

/**
 * JWT settings, validated at startup so a missing or weak
 * secret stops the application instead of failing on the
 * first login (JJWT rejects HMAC keys shorter than 256 bits).
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    /** HS256 requires a key of at least 256 bits. */
    public static final int MIN_SECRET_BYTES = 32;

    @NotBlank(message = "must be set (provide the JWT_SECRET environment variable)")
    private String secret;

    @Positive
    private long accessTokenExpiration;

    @Positive
    private long refreshTokenExpiration;

    /**
     * Configuration-properties binding leaves an unresolved
     * placeholder such as "${JWT_SECRET}" as a literal string
     * instead of failing, so detect it explicitly.
     */
    @AssertTrue(message = "jwt.secret is an unresolved placeholder; "
            + "set the JWT_SECRET environment variable")
    public boolean isSecretResolved() {
        return secret == null || !secret.contains("${");
    }

    @AssertTrue(message = "jwt.secret must be at least "
            + MIN_SECRET_BYTES + " bytes (256 bits) for HS256")
    public boolean isSecretLongEnough() {
        if (secret == null || secret.isBlank() || !isSecretResolved()) {
            // Reported by @NotBlank / isSecretResolved instead.
            return true;
        }
        return secret.getBytes(StandardCharsets.UTF_8).length
                >= MIN_SECRET_BYTES;
    }

}
