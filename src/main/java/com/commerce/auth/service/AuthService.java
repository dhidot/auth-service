package com.commerce.auth.service;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:07
Version 1.0
*/

import com.commerce.auth.dto.request.LoginRequest;
import com.commerce.auth.dto.request.LogoutRequest;
import com.commerce.auth.dto.request.RefreshTokenRequest;
import com.commerce.auth.dto.request.RegisterRequest;
import com.commerce.auth.dto.response.LoginResponse;
import com.commerce.auth.dto.response.RefreshTokenResponse;
import com.commerce.auth.dto.response.RegisterResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;

public interface AuthService {

    RegisterResponse register(RegisterRequest request);
    LoginResponse login(LoginRequest request, HttpServletRequest httpRequest);
    RefreshTokenResponse refreshToken(RefreshTokenRequest request, HttpServletRequest httpRequest);
    void logout(
            Authentication authentication,
            LogoutRequest request
    );
}