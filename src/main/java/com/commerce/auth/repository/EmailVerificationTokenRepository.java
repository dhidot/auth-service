package com.commerce.auth.repository;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 21:48
Version 1.0
*/
import com.commerce.auth.entity.EmailVerificationToken;
import com.commerce.auth.entity.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface EmailVerificationTokenRepository
        extends JpaRepository<EmailVerificationToken, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            SELECT t FROM EmailVerificationToken t
            WHERE t.tokenHash = :tokenHash
            """)
    Optional<EmailVerificationToken> findByTokenHashForUpdate(
            @Param("tokenHash") String tokenHash
    );
}