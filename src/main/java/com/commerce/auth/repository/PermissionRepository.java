package com.commerce.auth.repository;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 20:29
Version 1.0
*/

import com.commerce.auth.config.enums.PermissionName;
import com.commerce.auth.entity.Permission;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface PermissionRepository
        extends JpaRepository<Permission, UUID> {

    boolean existsByName(PermissionName name);

    Optional<Permission> findByName(PermissionName name);

}