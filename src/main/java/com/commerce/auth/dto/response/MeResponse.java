package com.commerce.auth.dto.response;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:06
Version 1.0
*/

import java.util.List;
import java.util.UUID;

public record MeResponse(

        UUID id,
        String username,
        String email,

        List<String> roles,
        List<String> permissions

) {
}
