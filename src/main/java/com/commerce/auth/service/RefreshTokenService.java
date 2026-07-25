package com.commerce.auth.service;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:39
Version 1.0
*/

import com.commerce.auth.entity.RefreshToken;
import com.commerce.auth.entity.User;

public interface RefreshTokenService {

    RefreshToken create(
            User user,
            String refreshToken,
            String deviceInfo,
            String ipAddress
    );

    RefreshToken validate(
            String refreshToken
    );

    void revoke(
            RefreshToken refreshToken
    );

}