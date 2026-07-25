package com.commerce.auth.dto.request;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:48
Version 1.0
*/

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(

        @NotBlank(message = "Email is required")
        @Email(message = "Invalid email format")
        String email,

        @NotBlank(message = "Password is required")
        String password

) {
}