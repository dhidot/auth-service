package com.commerce.auth.config;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 27/11/2026
Version 2.0
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
 * JWT settings (ADR 0001). Validated at startup so bad configuration
 * stops the application instead of failing on the first login.
 *
 * <ul>
 *   <li>{@code privateKey} (JWT_PRIVATE_KEY): RSA private key used to
 *       sign RS256 tokens. Required. Parsed and size-checked by
 *       {@link com.commerce.auth.security.jwt.JwtKeys}.</li>
 *   <li>{@code secret} (JWT_SECRET): legacy HS256 key. Optional; only
 *       used to <em>verify</em> tokens issued before the RS256 switch,
 *       during the 7-day transition. Never used to sign.</li>
 * </ul>
 */
@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    /** HS256 requires a key of at least 256 bits. */
    public static final int MIN_SECRET_BYTES = 32;

    @NotBlank(message = "must be set (provide the JWT_PRIVATE_KEY environment variable)")
    private String privateKey;

    /** Legacy HS256 verification key; empty disables legacy tokens. */
    private String secret;

    @NotBlank
    private String issuer = "careertrack-auth";

    @NotBlank
    private String audience = "careertrack-api";

    @Positive
    private long accessTokenExpiration;

    @Positive
    private long refreshTokenExpiration;

    /**
     * Configuration-properties binding leaves an unresolved
     * placeholder such as "${JWT_PRIVATE_KEY}" as a literal string
     * instead of failing, so detect it explicitly.
     */
    @AssertTrue(message = "jwt.private-key is an unresolved placeholder; "
            + "set the JWT_PRIVATE_KEY environment variable")
    public boolean isPrivateKeyResolved() {
        return privateKey == null || !privateKey.contains("${");
    }

    @AssertTrue(message = "jwt.secret is an unresolved placeholder; "
            + "set JWT_SECRET or leave it empty")
    public boolean isSecretResolved() {
        return secret == null || !secret.contains("${");
    }

    @AssertTrue(message = "jwt.secret must be at least "
            + MIN_SECRET_BYTES + " bytes (256 bits) for HS256")
    public boolean isSecretLongEnough() {
        if (!hasLegacySecret() || !isSecretResolved()) {
            return true;
        }
        return secret.getBytes(StandardCharsets.UTF_8).length
                >= MIN_SECRET_BYTES;
    }

    /** True when legacy HS256 tokens should still be accepted. */
    public boolean hasLegacySecret() {
        return secret != null && !secret.isBlank();
    }
}
