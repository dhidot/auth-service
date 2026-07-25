package com.commerce.auth.service.serviceImpl;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:08
Version 1.0
*/

import com.commerce.auth.dto.request.LoginRequest;
import com.commerce.auth.dto.request.LogoutRequest;
import com.commerce.auth.dto.request.RefreshTokenRequest;
import com.commerce.auth.dto.request.RegisterRequest;
import com.commerce.auth.dto.response.LoginResponse;
import com.commerce.auth.dto.response.RefreshTokenResponse;
import com.commerce.auth.dto.response.RegisterResponse;
import com.commerce.auth.entity.RefreshToken;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.BadRequestException;
import com.commerce.auth.exception.UnauthorizedException;
import com.commerce.auth.repository.RefreshTokenRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.security.jwt.JwtService;
import com.commerce.auth.service.AuthService;
import com.commerce.auth.service.RefreshTokenService;
import com.commerce.auth.utils.RequestUtils;
import com.commerce.auth.utils.TokenHasher;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;
import java.util.Optional;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {


    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    private void validateRegisterRequest(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new BadRequestException("Email already registered");
        }

        if (userRepository.existsByUsername(request.username())) {
            throw new BadRequestException("Username already registered");
        }
    }

    @Override
    public RegisterResponse register(RegisterRequest request) {

        validateRegisterRequest(request);

        String hashedPassword = passwordEncoder.encode(request.password());

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(hashedPassword)
                .tokenVersion(0)
                .build();

        User savedUser = userRepository.save(user);

        return new RegisterResponse(
                savedUser.getId(),
                savedUser.getUsername(),
                savedUser.getEmail()
        );
    }

    @Override
    public LoginResponse login(
            LoginRequest request,
            HttpServletRequest httpRequest
    ) {

        User user =
                userRepository.findByEmail(request.email())
                        .orElseThrow(() ->
                                new UnauthorizedException(
                                        "Invalid email or password"
                                ));


        if (!passwordEncoder.matches(
                request.password(),
                user.getPassword()
        )) {

            throw new UnauthorizedException(
                    "Invalid email or password"
            );
        }


        String accessToken =
                jwtService.generateAccessToken(user);


        String refreshToken =
                jwtService.generateRefreshToken(user);


        String deviceInfo =
                RequestUtils.getDeviceInfo(httpRequest);


        String ipAddress =
                RequestUtils.getClientIp(httpRequest);


        refreshTokenService.create(
                user,
                refreshToken,
                deviceInfo,
                ipAddress
        );


        return new LoginResponse(
                accessToken,
                refreshToken
        );

    }


    @Transactional
    @Override
    public RefreshTokenResponse refreshToken(
            RefreshTokenRequest request,
            HttpServletRequest httpRequest
    ) {

        String oldRefreshToken =
                request.refreshToken();


        // 1. Cari refresh token di database
        RefreshToken storedToken =
                refreshTokenService.validate(
                        oldRefreshToken
                );


        // 2. Ambil user pemilik token
        User user =
                storedToken.getUser();



        // 3. Validasi JWT refresh token
        if (!jwtService.isRefreshTokenValid(
                oldRefreshToken,
                user
        )) {

            throw new UnauthorizedException(
                    "Invalid refresh token"
            );
        }


        // 4. Update last used session lama
        storedToken.setLastUsedAt(
                LocalDateTime.now()
        );



        // 5. Revoke refresh token lama
        refreshTokenService.revoke(
                storedToken
        );



        // 6. Generate token baru

        String newAccessToken =
                jwtService.generateAccessToken(user);


        String newRefreshToken =
                jwtService.generateRefreshToken(user);



        // 7. Ambil device info terbaru

        String deviceInfo =
                RequestUtils.getDeviceInfo(
                        httpRequest
                );


        String ipAddress =
                RequestUtils.getClientIp(
                        httpRequest
                );



        // 8. Simpan refresh token baru

        refreshTokenService.create(
                user,
                newRefreshToken,
                deviceInfo,
                ipAddress
        );



        return new RefreshTokenResponse(
                newAccessToken,
                newRefreshToken
        );
    }

    @Override
    @Transactional
    public void logout(
            Authentication authentication,
            LogoutRequest request
    ) {


        String username =
                authentication.getName();

        String hash = TokenHasher.sha256(request.refreshToken());

        Optional<RefreshToken> refreshToken =
                refreshTokenRepository
                        .findByTokenHash(
                                hash
                        );


        if (!refreshToken.get().getUser()
                .getUsername()
                .equals(username)) {

            throw new UnauthorizedException(
                    "Invalid refresh token"
            );
        }


        refreshTokenService.revoke(
                refreshToken.orElse(null)
        );

    }

}
