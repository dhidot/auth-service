package com.commerce.auth.dto.request;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 00:06
Version 1.0
*/

import jakarta.validation.constraints.NotBlank;

public record LogoutRequest(

        @NotBlank(message = "Refresh token is required")
        String refreshToken

) {
}