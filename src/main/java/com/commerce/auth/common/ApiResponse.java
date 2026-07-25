package com.commerce.auth.common;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:24
Version 1.0
*/

import lombok.Builder;

@Builder
public record ApiResponse<T>(
        String code,
        String message,
        T data
) {
}
