package com.commerce.auth.repository;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:38
Version 1.0
*/

import com.commerce.auth.entity.RefreshToken;
import com.commerce.auth.entity.User;

import jakarta.persistence.LockModeType;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, UUID> {

    // Non-locking lookup, currently used by logout
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    // Locking lookup, exclusively for refresh token rotation
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT rt
            FROM RefreshToken rt
            WHERE rt.tokenHash = :tokenHash
            """)
    Optional<RefreshToken> findByTokenHashForUpdate(
            @Param("tokenHash") String tokenHash
    );

    List<RefreshToken> findAllByUserAndRevokedFalse(User user);

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        UPDATE RefreshToken rt
        SET rt.revoked = true
        WHERE rt.user.id = :userId
          AND rt.revoked = false
        """)
    int revokeAllActiveByUserId(
            @Param("userId") UUID userId
    );
}
