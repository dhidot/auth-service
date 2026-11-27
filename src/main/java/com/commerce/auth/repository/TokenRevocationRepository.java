package com.commerce.auth.repository;

import com.commerce.auth.entity.TokenRevocation;
import org.springframework.data.domain.Limit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface TokenRevocationRepository extends JpaRepository<TokenRevocation, Long> {

    /** Every revocation that can still affect an unexpired token. */
    List<TokenRevocation> findByExpiresAtAfterOrderByIdAsc(Instant now, Limit limit);

    boolean existsBySessionIdAndExpiresAtAfter(UUID sessionId, Instant now);

    @Modifying
    @Query("DELETE FROM TokenRevocation r WHERE r.expiresAt <= :now")
    int deleteExpired(@Param("now") Instant now);
}
