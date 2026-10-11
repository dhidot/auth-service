package com.commerce.auth.dto.request;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 20:07
Version 1.0
*/

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyEmailRequest(

        @NotBlank
        @Pattern(regexp = "^[A-Za-z0-9_-]{43}$")
        String token

) {
}