package com.commerce.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

/**
 * A short-lived revocation entry (ADR 0001, stage C2). See
 * V15__create_token_revocations.sql for the semantics.
 */
@Entity
@Table(name = "token_revocations")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TokenRevocation {

    public enum Type {
        /** Revokes every token carrying {@code sid = sessionId}. */
        SESSION,
        /** Revokes every token of the user issued before {@code notBefore}. */
        USER
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(name = "revocation_type", nullable = false, length = 16)
    private Type type;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "session_id")
    private UUID sessionId;

    @Column(name = "not_before")
    private Instant notBefore;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
}
