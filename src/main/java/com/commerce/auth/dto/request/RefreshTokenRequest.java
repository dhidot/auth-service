package com.commerce.auth.dto.request;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:17
Version 1.0
*/

import jakarta.validation.constraints.NotBlank;

public record RefreshTokenRequest(

        @NotBlank(message = "Refresh token is required")
        String refreshToken

) {}