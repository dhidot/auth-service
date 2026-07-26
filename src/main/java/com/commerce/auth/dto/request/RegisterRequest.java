package com.commerce.auth.dto.request;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:06
Version 1.0
*/

import com.commerce.auth.config.enums.RoleName;
import jakarta.validation.constraints.*;

public record RegisterRequest(

        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50)
        String username,

        @NotBlank(message = "Email is required")
        @Email(message = "Email format is invalid")
        @Pattern(
                regexp = "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$",
                message = "Email must contain a valid top-level domain"
        )
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 100,
                message = "Password must be between 8 and 100 characters")
        @Pattern(
                regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).*$",
                message = "Password must contain uppercase, lowercase, and number"
        )
        String password,

        @NotNull(message = "Role is required")
        RoleName role
) {
}