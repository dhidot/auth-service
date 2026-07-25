package com.commerce.auth.repository;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:05
Version 1.0
*/

import com.commerce.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmail(String email);

    Optional<User> findByUsername(String username);

    boolean existsByEmail(String email);

    boolean existsByUsername(String username);

}