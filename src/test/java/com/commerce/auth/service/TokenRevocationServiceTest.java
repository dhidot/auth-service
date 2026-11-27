package com.commerce.auth.service;

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.entity.TokenRevocation;
import com.commerce.auth.repository.TokenRevocationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TokenRevocationServiceTest {

    // 10:00:00.700 UTC
    private static final Instant NOW = Instant.parse("2026-11-27T10:00:00.700Z");

    private TokenRevocationRepository repository;
    private TokenRevocationService service;

    @BeforeEach
    void setUp() {
        repository = mock(TokenRevocationRepository.class);
        JwtProperties properties = new JwtProperties();
        properties.setAccessTokenExpiration(900_000L); // 15 min
        service = new TokenRevocationService(
                repository, properties, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    private TokenRevocation saved() {
        ArgumentCaptor<TokenRevocation> captor = ArgumentCaptor.forClass(TokenRevocation.class);
        verify(repository).save(captor.capture());
        return captor.getValue();
    }

    @Test
    void sessionRevocationLastsOneAccessTokenLifetimePlusMargin() {
        UUID user = UUID.randomUUID();
        UUID session = UUID.randomUUID();

        service.revokeSession(user, session);

        TokenRevocation r = saved();
        assertThat(r.getType()).isEqualTo(TokenRevocation.Type.SESSION);
        assertThat(r.getUserId()).isEqualTo(user);
        assertThat(r.getSessionId()).isEqualTo(session);
        assertThat(r.getNotBefore()).isNull();
        assertThat(r.getCreatedAt()).isEqualTo(NOW);
        // 15 min access token + 60 s margin for verifiers' clock skew
        assertThat(r.getExpiresAt()).isEqualTo(NOW.plusSeconds(900 + 60));
    }

    @Test
    void legacySessionWithoutSidRecordsNothing() {
        service.revokeSession(UUID.randomUUID(), null);

        verify(repository, never()).save(any());
    }

    @Test
    void userRevocationRoundsTheCutOffUpToTheNextSecond() {
        // iat has second precision: a token issued at 10:00:00.200 has
        // iat = 10:00:00, which must still count as "before" a revocation
        // made at 10:00:00.700. Cut-off 10:00:01 covers it.
        UUID user = UUID.randomUUID();

        service.revokeAllForUser(user);

        TokenRevocation r = saved();
        assertThat(r.getType()).isEqualTo(TokenRevocation.Type.USER);
        assertThat(r.getSessionId()).isNull();
        assertThat(r.getNotBefore()).isEqualTo(Instant.parse("2026-11-27T10:00:01Z"));
        assertThat(r.getExpiresAt()).isEqualTo(NOW.plusSeconds(960));
    }

    @Test
    void nullSessionIsNeverRevoked() {
        assertThat(service.isSessionRevoked(null)).isFalse();
        verifyNoInteractions(repository);
    }

    @Test
    void sessionCheckOnlyConsidersUnexpiredEntries() {
        UUID session = UUID.randomUUID();
        when(repository.existsBySessionIdAndExpiresAtAfter(session, NOW)).thenReturn(true);

        assertThat(service.isSessionRevoked(session)).isTrue();
    }

    @Test
    void purgeDeletesEntriesExpiredAtNow() {
        when(repository.deleteExpired(NOW)).thenReturn(3);

        service.purgeExpired();

        verify(repository).deleteExpired(NOW);
    }
}
