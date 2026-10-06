package com.commerce.auth.repository;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 21:48
Version 1.0
*/

import com.commerce.auth.entity.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

import com.commerce.auth.entity.EmailVerificationToken;
import com.commerce.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EmailVerificationTokenRepository
        extends JpaRepository<EmailVerificationToken, UUID> {

    Optional<EmailVerificationToken> findByToken(UUID token);

    @Modifying
    @Query("""
        UPDATE EmailVerificationToken t
           SET t.revoked = true
         WHERE t.user.id = :userId
           AND t.usedAt IS NULL
           AND t.revoked = false
    """)
    void revokeActiveTokens(UUID userId);

    List<EmailVerificationToken> findByUser(User user);

    void deleteByUser(User user);

}