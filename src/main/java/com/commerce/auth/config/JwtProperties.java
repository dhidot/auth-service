package com.commerce.auth.config;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:54
Version 1.0
*/

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    private String secret;

    private long accessTokenExpiration;

    private long refreshTokenExpiration;

}