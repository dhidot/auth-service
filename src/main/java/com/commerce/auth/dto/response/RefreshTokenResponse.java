package com.commerce.auth.dto.response;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:17
Version 1.0
*/

public record RefreshTokenResponse(

        String accessToken,

        String refreshToken

) {
}
