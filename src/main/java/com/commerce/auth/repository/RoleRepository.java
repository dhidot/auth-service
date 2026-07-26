package com.commerce.auth.repository;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 20:26
Version 1.0
*/

import com.commerce.auth.config.enums.RoleName;
import com.commerce.auth.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    Optional<Role> findByName(RoleName name);

    boolean existsByName(RoleName name);
}