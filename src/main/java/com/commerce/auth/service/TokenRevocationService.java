package com.commerce.auth.service;

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.entity.TokenRevocation;
import com.commerce.auth.repository.TokenRevocationRepository;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Limit;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

/**
 * Records and serves token revocations (ADR 0001, stage C2).
 *
 * <p>An entry only matters while a token it revokes can still be used,
 * i.e. for one access-token lifetime. It is kept for that lifetime plus
 * a margin covering the 30 s clock skew accepted by verifiers, then
 * purged.
 */
@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private static final Logger log = LoggerFactory.getLogger(TokenRevocationService.class);

    /** Covers the clock skew verifiers accept, with room to spare. */
    static final Duration RETENTION_MARGIN = Duration.ofSeconds(60);

    /** Upper bound for one snapshot; far above realistic volume. */
    public static final int MAX_ENTRIES = 10_000;

    private final TokenRevocationRepository repository;
    private final JwtProperties jwtProperties;
    private final Clock clock;

    /**
     * Logout of one session. Tokens issued before ADR 0001 carry no
     * {@code sid}; their access cookie is already cleared by the BFF and
     * they expire within the access-token lifetime.
     */
    @Transactional
    public void revokeSession(UUID userId, UUID sessionId) {
        if (sessionId == null) {
            log.debug("logout of a legacy session without sid; nothing to revoke");
            return;
        }
        Instant now = clock.instant();
        repository.save(TokenRevocation.builder()
                .type(TokenRevocation.Type.SESSION)
                .userId(userId)
                .sessionId(sessionId)
                .createdAt(now)
                .expiresAt(expiryFrom(now))
                .build());
    }

    /**
     * Logout-all (and later suspension / password change): every token of
     * the user issued before now. {@code iat} has second precision, so the
     * cut-off is rounded up to the next second: a token issued in the same
     * second as the revocation is treated as revoked. Revoking one token
     * too many is safer than missing one.
     */
    @Transactional
    public void revokeAllForUser(UUID userId) {
        Instant now = clock.instant();
        Instant notBefore = now.truncatedTo(ChronoUnit.SECONDS).plusSeconds(1);
        repository.save(TokenRevocation.builder()
                .type(TokenRevocation.Type.USER)
                .userId(userId)
                .notBefore(notBefore)
                .createdAt(now)
                .expiresAt(expiryFrom(now))
                .build());
    }

    @Transactional(readOnly = true)
    public boolean isSessionRevoked(UUID sessionId) {
        return sessionId != null
                && repository.existsBySessionIdAndExpiresAtAfter(sessionId, clock.instant());
    }

    /** All entries that can still affect an unexpired token. */
    @Transactional(readOnly = true)
    public List<TokenRevocation> activeRevocations() {
        return repository.findByExpiresAtAfterOrderByIdAsc(clock.instant(), Limit.of(MAX_ENTRIES));
    }

    @Scheduled(fixedDelayString = "PT10M", initialDelayString = "PT1M")
    @Transactional
    public void purgeExpired() {
        int deleted = repository.deleteExpired(clock.instant());
        if (deleted > 0) {
            log.info("purged {} expired token revocations", deleted);
        }
    }

    Instant expiryFrom(Instant now) {
        return now.plusMillis(jwtProperties.getAccessTokenExpiration()).plus(RETENTION_MARGIN);
    }
}
