package com.commerce.auth.security.jwt;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 27/11/2026
Version 2.0
*/

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.entity.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.IncorrectClaimException;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.LocatorAdapter;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;

import lombok.RequiredArgsConstructor;

import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Issues and verifies JWTs according to ADR 0001.
 *
 * <p><b>Issued tokens</b> (always): RS256, header {@code kid}, claims
 * {@code iss}, {@code aud}, {@code sub} = user UUID, {@code sid},
 * {@code username} (display only), {@code type}, {@code tokenVersion},
 * {@code jti}, {@code iat}, {@code exp}.
 *
 * <p><b>Accepted tokens</b>:
 * <ul>
 *   <li>RS256 signed by our key ({@code kid} must match), with the
 *       expected {@code iss} and {@code aud}.</li>
 *   <li>Transition only: legacy HS256 tokens (sub = username, no
 *       iss/aud) while {@code jwt.secret} is still configured.</li>
 * </ul>
 * Everything else is rejected, including {@code alg: none} and the
 * classic confusion attack of an HS256 token "signed" with the public
 * key: the HMAC key is only ever the legacy secret, never the RSA key.
 */
@Service
@RequiredArgsConstructor
public class JwtServiceImpl implements JwtService {

    static final String ACCESS = "ACCESS";
    static final String REFRESH = "REFRESH";

    static final String CLAIM_TYPE = "type";
    static final String CLAIM_TOKEN_VERSION = "tokenVersion";
    static final String CLAIM_SESSION = "sid";
    static final String CLAIM_USERNAME = "username";

    private static final String RS256 = "RS256";
    private static final Set<String> LEGACY_HMAC_ALGORITHMS = Set.of("HS256", "HS384", "HS512");
    private static final long CLOCK_SKEW_SECONDS = 30;

    private final JwtProperties jwtProperties;
    private final JwtKeys jwtKeys;

    // ------------------------------------------------------------------
    // Issue
    // ------------------------------------------------------------------

    private String generateToken(
            User user,
            UUID sessionId,
            String type,
            long expirationMillis
    ) {
        Objects.requireNonNull(user.getId(), "user must be persisted (id is the subject)");
        Objects.requireNonNull(sessionId, "sessionId");

        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationMillis);

        return Jwts.builder()
                .header().keyId(jwtKeys.keyId()).and()
                .id(UUID.randomUUID().toString())
                .issuer(jwtProperties.getIssuer())
                .audience().add(jwtProperties.getAudience()).and()
                .subject(user.getId().toString())
                .claim(CLAIM_SESSION, sessionId.toString())
                .claim(CLAIM_USERNAME, user.getUsername())
                .claim(CLAIM_TYPE, type)
                .claim(CLAIM_TOKEN_VERSION, user.getTokenVersion())
                .issuedAt(now)
                .expiration(expiration)
                .signWith(jwtKeys.privateKey(), Jwts.SIG.RS256)
                .compact();
    }

    @Override
    public String generateAccessToken(User user, UUID sessionId) {
        return generateToken(user, sessionId, ACCESS, jwtProperties.getAccessTokenExpiration());
    }

    @Override
    public String generateRefreshToken(User user, UUID sessionId) {
        return generateToken(user, sessionId, REFRESH, jwtProperties.getRefreshTokenExpiration());
    }

    // ------------------------------------------------------------------
    // Verify
    // ------------------------------------------------------------------

    /**
     * Picks the verification key from the token header. Unknown
     * algorithms or key ids resolve to an exception, so the token is
     * rejected before any signature check.
     */
    private final LocatorAdapter<Key> keyLocator = new LocatorAdapter<>() {
        @Override
        protected Key locate(JwsHeader header) {
            String alg = header.getAlgorithm();

            if (RS256.equals(alg)) {
                if (!jwtKeys.keyId().equals(header.getKeyId())) {
                    throw new SignatureException("Unknown signing key");
                }
                return jwtKeys.publicKey();
            }

            // The previous version called signWith(key) without an
            // algorithm, so JJWT picked HS256/384/512 from the secret's
            // length. Production tokens can be any of the three.
            if (LEGACY_HMAC_ALGORITHMS.contains(alg)) {
                return jwtKeys.legacyHmacKey()
                        .orElseThrow(() -> new UnsupportedJwtException(
                                "Legacy HMAC tokens are no longer accepted"));
            }

            throw new UnsupportedJwtException("Unsupported JWT algorithm");
        }

        @Override
        protected Key doLocate(Header header) {
            // Unsecured (alg: none) or encrypted tokens.
            throw new UnsupportedJwtException("Only signed JWTs are accepted");
        }
    };

    @Override
    public Claims extractAllClaims(String token) {
        var jws = Jwts.parser()
                .keyLocator(keyLocator)
                .clockSkewSeconds(CLOCK_SKEW_SECONDS)
                .build()
                .parseSignedClaims(token);

        Claims claims = jws.getPayload();

        if (RS256.equals(jws.getHeader().getAlgorithm())) {
            requireIssuerAndAudience(claims);
        }

        return claims;
    }

    private void requireIssuerAndAudience(Claims claims) {
        if (!jwtProperties.getIssuer().equals(claims.getIssuer())) {
            throw new IncorrectClaimException(
                    null, claims, Claims.ISSUER, jwtProperties.getIssuer(),
                    "Unexpected token issuer");
        }
        Set<String> audience = claims.getAudience();
        if (audience == null || !audience.contains(jwtProperties.getAudience())) {
            throw new IncorrectClaimException(
                    null, claims, Claims.AUDIENCE, jwtProperties.getAudience(),
                    "Unexpected token audience");
        }
    }

    @Override
    public String extractSubject(String token) {
        return extractAllClaims(token).getSubject();
    }

    /**
     * Subject matches the user: UUID for current tokens; username only
     * for legacy tokens (no {@code iss}), which never carry a UUID sub.
     */
    private static boolean subjectMatches(Claims claims, User user) {
        String subject = claims.getSubject();
        if (subject == null) {
            return false;
        }
        if (claims.getIssuer() != null) {
            return user.getId() != null && subject.equals(user.getId().toString());
        }
        return subject.equals(user.getUsername());
    }

    private boolean hasValidCommonClaims(
            Claims claims,
            User user
    ) {

        if (user == null || !user.isAccountActive()) {
            return false;
        }

        Integer tokenVersion =
                claims.get(CLAIM_TOKEN_VERSION, Integer.class);

        return subjectMatches(claims, user)
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
                claims.get(CLAIM_TYPE, String.class)
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
                claims.get(CLAIM_TYPE, String.class)
        )
                && hasValidCommonClaims(claims, user);
    }
}
