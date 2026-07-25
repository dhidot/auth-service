package com.commerce.auth.controller;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:09
Version 1.0
*/

import com.commerce.auth.common.ApiResponse;
import com.commerce.auth.dto.request.LoginRequest;
import com.commerce.auth.dto.request.LogoutRequest;
import com.commerce.auth.dto.request.RefreshTokenRequest;
import com.commerce.auth.dto.request.RegisterRequest;
import com.commerce.auth.dto.response.LoginResponse;
import com.commerce.auth.dto.response.MeResponse;
import com.commerce.auth.dto.response.RefreshTokenResponse;
import com.commerce.auth.dto.response.RegisterResponse;
import com.commerce.auth.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {


    private final AuthService authService;


    @PostMapping("/register")
    public ResponseEntity<ApiResponse<RegisterResponse>> register(
            @Valid @RequestBody RegisterRequest request
    ) {

        RegisterResponse response = authService.register(request);

        return ResponseEntity.ok(
                ApiResponse.<RegisterResponse>builder()
                        .code("200")
                        .message("Register success")
                        .data(response)
                        .build()
        );
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest
    ) {

        LoginResponse response = authService.login(request, httpRequest);

        return ResponseEntity.ok(
                ApiResponse.<LoginResponse>builder()
                        .code("200")
                        .message("Login success")
                        .data(response)
                        .build()
        );
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<MeResponse>> me(
            Authentication authentication
    ) {

        List<String> authorities = authentication
                .getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        MeResponse response = new MeResponse(
                authentication.getName(),
                authorities
        );

        return ResponseEntity.ok(
                ApiResponse.<MeResponse>builder()
                        .code("200")
                        .message("Success")
                        .data(response)
                        .build()
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<RefreshTokenResponse>> refresh(
            @Valid @RequestBody RefreshTokenRequest request, HttpServletRequest httpRequest
    ) {

        RefreshTokenResponse response =
                authService.refreshToken(request, httpRequest);


        return ResponseEntity.ok(
                ApiResponse.<RefreshTokenResponse>builder()
                        .code("200")
                        .message("Token refreshed successfully")
                        .data(response)
                        .build()
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            Authentication authentication,
            @Valid @RequestBody LogoutRequest request
    ) {

        authService.logout(
                authentication,
                request
        );


        return ResponseEntity.ok(
                ApiResponse.<Void>builder()
                        .code("200")
                        .message("Logout successfully")
                        .build()
        );
    }

}
