package com.commerce.auth.config;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 20:42
Version 1.0
*/

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.admin")
public class AdminProperties {

    private String username;

    private String email;

    private String password;

}