package com.commerce.auth.security.jwt;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 27/11/2026
Version 2.0
*/

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.entity.User;
import com.commerce.auth.support.TestJwtKeys;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.security.Keys;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceImplTest {

    private static final String LEGACY_SECRET =
            "legacy-hs256-secret-for-tests-0123456789abcdef";

    private JwtProperties properties;
    private JwtKeys keys;
    private JwtServiceImpl jwtService;

    @BeforeEach
    void setUp() {
        properties = new JwtProperties();
        properties.setPrivateKey(TestJwtKeys.pem(TestJwtKeys.shared()));
        properties.setAccessTokenExpiration(900_000L);
        properties.setRefreshTokenExpiration(604_800_000L);
        rebuild();
    }

    private void rebuild() {
        keys = new JwtKeys(properties);
        jwtService = new JwtServiceImpl(properties, keys);
    }

    private User activeUser() {
        return User.builder()
                .id(UUID.randomUUID())
                .username("dhito")
                .tokenVersion(0)
                .accountStatus(AccountStatus.ACTIVE)
                .enabled(true)
                .emailVerified(true)
                .build();
    }

    // =================================================================
    // Issued token format (ADR 0001)
    // =================================================================

    @Test
    void accessToken_followsTheContract() {
        User user = activeUser();
        UUID session = UUID.randomUUID();

        String token = jwtService.generateAccessToken(user, session);
        var jws = Jwts.parser().verifyWith(keys.publicKey()).build().parseSignedClaims(token);
        Claims claims = jws.getPayload();

        assertEquals("RS256", jws.getHeader().getAlgorithm());
        assertEquals(keys.keyId(), jws.getHeader().getKeyId());
        assertEquals("careertrack-auth", claims.getIssuer());
        assertTrue(claims.getAudience().contains("careertrack-api"));
        assertEquals(user.getId().toString(), claims.getSubject());
        assertEquals(session.toString(), claims.get("sid", String.class));
        assertEquals("dhito", claims.get("username", String.class));
        assertEquals("ACCESS", claims.get("type", String.class));
        assertEquals(0, claims.get("tokenVersion", Integer.class));
        assertNotNull(claims.getId());
        assertNotNull(claims.getExpiration());
    }

    @Test
    void accessAndRefreshTokenShareTheSession() {
        User user = activeUser();
        UUID session = UUID.randomUUID();

        Claims access = jwtService.extractAllClaims(jwtService.generateAccessToken(user, session));
        Claims refresh = jwtService.extractAllClaims(jwtService.generateRefreshToken(user, session));

        assertEquals(access.get("sid"), refresh.get("sid"));
        assertEquals("REFRESH", refresh.get("type", String.class));
    }

    @Test
    void refreshTokensAreUnique() {
        User user = activeUser();

        String first = jwtService.generateRefreshToken(user);
        String second = jwtService.generateRefreshToken(user);

        assertNotEquals(first, second);
        assertNotEquals(
                jwtService.extractAllClaims(first).getId(),
                jwtService.extractAllClaims(second).getId()
        );
    }

    @Test
    void extractSubject_returnsTheUserId() {
        User user = activeUser();

        assertEquals(user.getId().toString(),
                jwtService.extractSubject(jwtService.generateAccessToken(user)));
    }

    @Test
    void cannotIssueATokenForAnUnsavedUser() {
        User unsaved = activeUser();
        unsaved.setId(null);

        assertThrows(NullPointerException.class, () -> jwtService.generateAccessToken(unsaved));
    }

    // =================================================================
    // Validation rules carried over from the HS256 version
    // =================================================================

    @Test
    void refreshToken_whenTokenVersionChanges_isRejected() {
        User user = activeUser();
        String token = jwtService.generateRefreshToken(user);

        assertTrue(jwtService.isRefreshTokenValid(token, user));

        user.setTokenVersion(1);

        assertFalse(jwtService.isRefreshTokenValid(token, user));
    }

    @Test
    void refreshToken_isNotAnAccessToken() {
        User user = activeUser();

        assertFalse(jwtService.isTokenValid(jwtService.generateRefreshToken(user), user));
    }

    @Test
    void accessToken_isNotARefreshToken() {
        User user = activeUser();

        assertFalse(jwtService.isRefreshTokenValid(jwtService.generateAccessToken(user), user));
    }

    @Test
    void tokens_whenAccountSuspended_areRejected() {
        User user = activeUser();
        String access = jwtService.generateAccessToken(user);
        String refresh = jwtService.generateRefreshToken(user);

        user.setAccountStatus(AccountStatus.SUSPENDED);
        user.setEnabled(false);

        assertFalse(jwtService.isTokenValid(access, user));
        assertFalse(jwtService.isRefreshTokenValid(refresh, user));
    }

    @Test
    void token_forAnotherUser_isRejected() {
        User owner = activeUser();
        User other = activeUser();

        assertFalse(jwtService.isTokenValid(jwtService.generateAccessToken(owner), other));
    }

    @Test
    void expiredToken_throws() {
        // Allowed clock skew is 30 s, so build an explicitly old token.
        String old = Jwts.builder()
                .header().keyId(keys.keyId()).and()
                .issuer("careertrack-auth").audience().add("careertrack-api").and()
                .subject(UUID.randomUUID().toString())
                .expiration(new Date(System.currentTimeMillis() - 120_000))
                .signWith(keys.privateKey(), Jwts.SIG.RS256)
                .compact();

        assertThrows(ExpiredJwtException.class, () -> jwtService.extractAllClaims(old));
    }

    // =================================================================
    // Attacks and wrong tokens
    // =================================================================

    @Test
    void wrongIssuer_isRejected() {
        String token = Jwts.builder()
                .header().keyId(keys.keyId()).and()
                .issuer("someone-else").audience().add("careertrack-api").and()
                .subject(UUID.randomUUID().toString())
                .signWith(keys.privateKey(), Jwts.SIG.RS256)
                .compact();

        assertThrows(JwtException.class, () -> jwtService.extractAllClaims(token));
    }

    @Test
    void wrongAudience_isRejected() {
        String token = Jwts.builder()
                .header().keyId(keys.keyId()).and()
                .issuer("careertrack-auth").audience().add("another-api").and()
                .subject(UUID.randomUUID().toString())
                .signWith(keys.privateKey(), Jwts.SIG.RS256)
                .compact();

        assertThrows(JwtException.class, () -> jwtService.extractAllClaims(token));
    }

    @Test
    void tokenSignedByAnotherKey_isRejected_evenWithOurKid() {
        KeyPair attacker = TestJwtKeys.generate(2048);

        String token = Jwts.builder()
                .header().keyId(keys.keyId()).and()
                .issuer("careertrack-auth").audience().add("careertrack-api").and()
                .subject(UUID.randomUUID().toString())
                .signWith(attacker.getPrivate(), Jwts.SIG.RS256)
                .compact();

        assertThrows(JwtException.class, () -> jwtService.extractAllClaims(token));
    }

    @Test
    void unknownKid_isRejected() {
        String token = Jwts.builder()
                .header().keyId("not-our-key").and()
                .issuer("careertrack-auth").audience().add("careertrack-api").and()
                .subject(UUID.randomUUID().toString())
                .signWith(keys.privateKey(), Jwts.SIG.RS256)
                .compact();

        assertThrows(JwtException.class, () -> jwtService.extractAllClaims(token));
    }

    @Test
    void unsignedAlgNoneToken_isRejected() {
        String header = b64("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        String payload = b64("{\"iss\":\"careertrack-auth\",\"aud\":\"careertrack-api\","
                + "\"sub\":\"" + UUID.randomUUID() + "\",\"type\":\"ACCESS\",\"tokenVersion\":0}");

        assertThrows(JwtException.class, () -> jwtService.extractAllClaims(header + "." + payload + "."));
    }

    @Test
    void hs256SignedWithThePublicKey_isRejected() {
        // Classic algorithm-confusion attack: use the (public) RSA key
        // bytes as an HMAC secret. Must fail even with a legacy secret on.
        properties.setSecret(LEGACY_SECRET);
        rebuild();

        String token = Jwts.builder()
                .issuer("careertrack-auth").audience().add("careertrack-api").and()
                .subject(UUID.randomUUID().toString())
                .claim("type", "ACCESS")
                .signWith(Keys.hmacShaKeyFor(keys.publicKey().getEncoded()), Jwts.SIG.HS256)
                .compact();

        assertThrows(JwtException.class, () -> jwtService.extractAllClaims(token));
    }

    // =================================================================
    // Transition: legacy HS256 tokens (ADR 0001, stage B)
    // =================================================================

    private String legacyToken(User user, String type) {
        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getUsername())
                .claim("type", type)
                .claim("tokenVersion", user.getTokenVersion())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 900_000))
                .signWith(Keys.hmacShaKeyFor(LEGACY_SECRET.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS256)
                .compact();
    }

    @Test
    void legacyToken_isAcceptedWhileTheSecretIsConfigured() {
        properties.setSecret(LEGACY_SECRET);
        rebuild();
        User user = activeUser();

        assertEquals("dhito", jwtService.extractSubject(legacyToken(user, "ACCESS")));
        assertTrue(jwtService.isTokenValid(legacyToken(user, "ACCESS"), user));
        assertTrue(jwtService.isRefreshTokenValid(legacyToken(user, "REFRESH"), user));
    }

    @Test
    void legacyToken_isAcceptedWhateverHmacStrengthTheOldVersionPicked() {
        // Old code: signWith(key) without an algorithm, so JJWT chose
        // HS256/384/512 from the secret length (64+ bytes -> HS512).
        String longSecret = "x".repeat(64);
        properties.setSecret(longSecret);
        rebuild();
        User user = activeUser();

        String hs512 = Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(user.getUsername())
                .claim("type", "ACCESS")
                .claim("tokenVersion", 0)
                .expiration(new Date(System.currentTimeMillis() + 900_000))
                .signWith(Keys.hmacShaKeyFor(longSecret.getBytes(StandardCharsets.UTF_8)))
                .compact();

        String header = new String(
                Base64.getUrlDecoder().decode(hs512.substring(0, hs512.indexOf('.'))),
                StandardCharsets.UTF_8);
        assertTrue(header.contains("\"HS512\""), header);
        assertTrue(jwtService.isTokenValid(hs512, user));
    }

    @Test
    void legacyToken_isRejectedOnceTheSecretIsRemoved() {
        User user = activeUser();

        assertThrows(JwtException.class, () -> jwtService.extractAllClaims(legacyToken(user, "ACCESS")));
    }

    @Test
    void legacyToken_forAnotherUsername_isRejected() {
        properties.setSecret(LEGACY_SECRET);
        rebuild();
        User owner = activeUser();
        User other = activeUser();
        other.setUsername("someone-else");

        assertFalse(jwtService.isTokenValid(legacyToken(owner, "ACCESS"), other));
    }

    @Test
    void newTokenWithAUsernameSubject_isRejected() {
        // A current (RS256, with iss) token must carry a UUID subject.
        User user = activeUser();
        String token = Jwts.builder()
                .header().keyId(keys.keyId()).and()
                .id(UUID.randomUUID().toString())
                .issuer("careertrack-auth").audience().add("careertrack-api").and()
                .subject(user.getUsername())
                .claim("type", "ACCESS")
                .claim("tokenVersion", 0)
                .expiration(new Date(System.currentTimeMillis() + 900_000))
                .signWith(keys.privateKey(), Jwts.SIG.RS256)
                .compact();

        assertFalse(jwtService.isTokenValid(token, user));
    }

    private static String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }
}
