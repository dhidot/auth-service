package com.commerce.auth.security.jwt;

import com.commerce.auth.config.JwtProperties;
import io.jsonwebtoken.security.Jwks;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.RsaPublicJwk;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

/**
 * Signing material for JWTs (ADR 0001).
 *
 * <p>Parses {@code jwt.private-key} once at startup and fails fast with a
 * clear message if it is missing, malformed, not RSA or shorter than
 * {@value #MIN_RSA_BITS} bits. The public key is derived from the private
 * key, so only one secret has to be configured. The key id ({@code kid})
 * is the RFC 7638 thumbprint of the public key: it changes automatically
 * when the key is rotated.
 *
 * <p>Accepted formats for {@code jwt.private-key} (JWT_PRIVATE_KEY):
 * <ul>
 *   <li>PKCS#8 PEM ({@code -----BEGIN PRIVATE KEY-----}), e.g. from
 *       {@code openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048}</li>
 *   <li>the same PEM, base64-encoded on one line (easier in .env files)</li>
 * </ul>
 */
@Component
public class JwtKeys {

    public static final int MIN_RSA_BITS = 2048;

    private final RSAPrivateCrtKey privateKey;
    private final RSAPublicKey publicKey;
    private final RsaPublicJwk publicJwk;
    private final SecretKey legacyHmacKey;

    public JwtKeys(JwtProperties properties) {
        this.privateKey = parsePrivateKey(properties.getPrivateKey());
        this.publicKey = derivePublicKey(privateKey);
        this.publicJwk = Jwks.builder()
                .key(publicKey)
                .algorithm("RS256")
                .publicKeyUse("sig")
                .idFromThumbprint()
                .build();
        this.legacyHmacKey = properties.hasLegacySecret()
                ? Keys.hmacShaKeyFor(properties.getSecret().getBytes(StandardCharsets.UTF_8))
                : null;
    }

    public RSAPrivateCrtKey privateKey() {
        return privateKey;
    }

    public RSAPublicKey publicKey() {
        return publicKey;
    }

    public String keyId() {
        return publicJwk.getId();
    }

    /** JWKS document served at /.well-known/jwks.json. */
    public Map<String, Object> jwks() {
        return Map.of("keys", java.util.List.of(publicJwk));
    }

    /** HS256 key for verifying pre-RS256 tokens, if still configured. */
    public Optional<SecretKey> legacyHmacKey() {
        return Optional.ofNullable(legacyHmacKey);
    }

    // ------------------------------------------------------------------

    static RSAPrivateCrtKey parsePrivateKey(String configured) {
        if (configured == null || configured.isBlank()) {
            throw new IllegalStateException(
                    "jwt.private-key is not set; provide JWT_PRIVATE_KEY (PKCS#8 PEM)");
        }

        String pem = configured.trim();

        if (!pem.contains("-----BEGIN")) {
            // Base64-encoded PEM on a single line.
            try {
                pem = new String(Base64.getMimeDecoder().decode(pem), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException(
                        "jwt.private-key is neither PEM nor base64-encoded PEM");
            }
        }

        // .env files often store newlines as literal "\n".
        pem = pem.replace("\\n", "\n");

        if (pem.contains("BEGIN RSA PRIVATE KEY")) {
            throw new IllegalStateException(
                    "jwt.private-key is PKCS#1; convert it with "
                            + "'openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem'");
        }
        if (!pem.contains("BEGIN PRIVATE KEY")) {
            throw new IllegalStateException(
                    "jwt.private-key must be an unencrypted PKCS#8 PEM "
                            + "(-----BEGIN PRIVATE KEY-----)");
        }

        String base64 = pem
                .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");

        try {
            byte[] der = Base64.getDecoder().decode(base64);
            var key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));

            if (!(key instanceof RSAPrivateCrtKey rsa)) {
                throw new IllegalStateException("jwt.private-key must be an RSA key");
            }
            if (rsa.getModulus().bitLength() < MIN_RSA_BITS) {
                throw new IllegalStateException(
                        "jwt.private-key must be at least " + MIN_RSA_BITS + " bits, was "
                                + rsa.getModulus().bitLength());
            }
            return rsa;
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            // Do not include the key material or parser details.
            throw new IllegalStateException(
                    "jwt.private-key could not be parsed as an RSA PKCS#8 key");
        }
    }

    private static RSAPublicKey derivePublicKey(RSAPrivateCrtKey privateKey) {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
        } catch (Exception e) {
            throw new IllegalStateException("Could not derive the RSA public key", e);
        }
    }
}
