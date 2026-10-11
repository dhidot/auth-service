package com.commerce.auth.repository;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:05
Version 1.0
*/

import com.commerce.auth.entity.User;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    @EntityGraph(attributePaths = {
            "roles",
            "roles.permissions"
    })
    Optional<User> findByEmail(String email);

    @EntityGraph(attributePaths = {
            "roles",
            "roles.permissions"
    })
    Optional<User> findByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
        SELECT u
        FROM User u
        WHERE u.id = :userId
        """)
    Optional<User> findByIdForUpdate(
            @Param("userId") UUID userId
    );

    @Modifying(flushAutomatically = true, clearAutomatically = true)
    @Query("""
        UPDATE User u
        SET u.tokenVersion = u.tokenVersion + 1
        WHERE u.id = :userId
        """)
    int incrementTokenVersion(@Param("userId") UUID userId);

    @EntityGraph(attributePaths = {
            "roles",
            "roles.permissions"
    })
    @Query("""
        SELECT u
        FROM User u
        WHERE u.username = :username
        """)
    Optional<User> findByUsernameWithAuthorities(
            @Param("username") String username
    );
}