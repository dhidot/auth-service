package com.commerce.auth.repository;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:38
Version 1.0
*/

import com.commerce.auth.entity.RefreshToken;
import com.commerce.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findAllByUserAndRevokedFalse(User user);

}