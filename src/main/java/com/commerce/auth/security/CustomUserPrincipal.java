package com.commerce.auth.security;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:28
Version 1.0
*/

import com.commerce.auth.entity.Role;
import com.commerce.auth.entity.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Set;
import java.util.UUID;

@Getter
public class CustomUserPrincipal implements UserDetails {

    private final User user;
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomUserPrincipal(
            User user,
            Collection<? extends GrantedAuthority> authorities
    ) {
        this.user = user;
        this.authorities = authorities;
    }

    public UUID getId() {
        return user.getId();
    }

    public String getEmail() {
        return user.getEmail();
    }

    public Set<Role> getRoles() {
        return user.getRoles();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }
}