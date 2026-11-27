package com.commerce.auth.security;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:03
Version 1.0
*/

import com.commerce.auth.entity.User;
import com.commerce.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import java.util.UUID;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Loads the user named by a token's {@code sub}: a UUID for current
     * tokens, or a username for legacy tokens during the transition
     * (ADR 0001, stage B).
     */
    public UserDetails loadUserBySubject(String subject) {
        UUID id = parseUuid(subject);

        if (id == null) {
            return loadUserByUsername(subject);
        }

        User user = userRepository.findWithAuthoritiesById(id)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found"));

        return new UserPrincipal(user);
    }

    private static UUID parseUuid(String value) {
        if (value == null || value.length() != 36) {
            return null;
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) {

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found"));

        return new UserPrincipal(user);
    }
}