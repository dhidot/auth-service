package com.commerce.auth.config;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 20:30
Version 1.0
*/

import com.commerce.auth.config.enums.PermissionName;
import com.commerce.auth.config.enums.RoleName;
import com.commerce.auth.entity.Permission;
import com.commerce.auth.entity.Role;
import com.commerce.auth.entity.User;
import com.commerce.auth.repository.PermissionRepository;
import com.commerce.auth.repository.RoleRepository;
import com.commerce.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Configuration
@RequiredArgsConstructor
public class DataSeeder {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminProperties adminProperties;

    @Bean
    CommandLineRunner seedDatabase() {

        return args -> {

            seedRoles();

            seedPermissions();

            seedRolePermissions();

            seedAdmin();

        };

    }

    private void seedRoles() {

        for (RoleName roleName : RoleName.values()) {

            if (!roleRepository.existsByName(roleName)) {

                Role role = Role.builder()
                        .name(roleName)
                        .build();

                roleRepository.save(role);
            }
        }
    }

    private void seedPermissions() {

        for (PermissionName permissionName : PermissionName.values()) {

            if (!permissionRepository.existsByName(permissionName)) {

                Permission permission = Permission.builder()
                        .name(permissionName)
                        .build();

                permissionRepository.save(permission);

            }

        }

    }


    // ROLE PERMISSIONS
    private Role getRole(RoleName roleName) {

        return roleRepository.findByName(roleName)
                .orElseThrow();

    }

    private Permission getPermission(
            PermissionName permissionName
    ) {

        return permissionRepository.findByName(permissionName)
                .orElseThrow();

    }

    private void assignPermissions(
            RoleName roleName,
            PermissionName... permissionNames
    ) {

        Role role = getRole(roleName);

        Set<Permission> permissions = Arrays.stream(permissionNames)
                .map(this::getPermission)
                .collect(Collectors.toSet());

        role.setPermissions(permissions);

        roleRepository.save(role);
    }

    private void seedRolePermissions() {

        Role superAdmin = getRole(RoleName.SUPER_ADMIN);

        superAdmin.setPermissions(
                new HashSet<>(permissionRepository.findAll())
        );

        roleRepository.save(superAdmin);

        assignPermissions(
                RoleName.ADMIN,
                PermissionName.USER_READ,
                PermissionName.USER_UPDATE,
                PermissionName.ROLE_READ,
                PermissionName.ORDER_READ,
                PermissionName.ORDER_UPDATE,
                PermissionName.PAYMENT_VERIFY
        );

        assignPermissions(
                RoleName.SELLER,
                PermissionName.PRODUCT_CREATE,
                PermissionName.PRODUCT_UPDATE,
                PermissionName.ORDER_READ
        );

        assignPermissions(
                RoleName.CUSTOMER,
                PermissionName.ORDER_CREATE,
                PermissionName.ORDER_CANCEL
        );

    }

    private void seedAdmin() {

        if (userRepository.existsByEmail(
                adminProperties.getEmail()
        )) {
            return;
        }

        Role superAdmin =
                getRole(RoleName.SUPER_ADMIN);

        User admin =
                User.builder()
                        .username(adminProperties.getUsername())
                        .email(adminProperties.getEmail())
                        .password(
                                passwordEncoder.encode(
                                        adminProperties.getPassword()
                                )
                        )
                        .tokenVersion(0)
                        .build();

        admin.getRoles().add(superAdmin);

        userRepository.save(admin);

    }

}