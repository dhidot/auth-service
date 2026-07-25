package com.commerce.auth.dto.response;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:49
Version 1.0
*/

import java.util.UUID;

public record LoginResponse(

        String accessToken,

        String refreshToken

) {
}