package com.commerce.auth.dto.response;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:06
Version 1.0
*/

import java.util.List;

public record MeResponse(

        String email,

        List<String> authorities

) {
}
