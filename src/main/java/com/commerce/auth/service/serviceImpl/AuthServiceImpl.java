package com.commerce.auth.service.serviceImpl;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 22:08
Version 1.0
*/

import com.commerce.auth.config.enums.AccountStatus;
import com.commerce.auth.config.enums.RoleName;
import com.commerce.auth.dto.request.LoginRequest;
import com.commerce.auth.dto.request.LogoutRequest;
import com.commerce.auth.dto.request.RefreshTokenRequest;
import com.commerce.auth.dto.request.RegisterRequest;
import com.commerce.auth.dto.response.LoginResponse;
import com.commerce.auth.dto.response.RefreshTokenResponse;
import com.commerce.auth.dto.response.RegisterResponse;
import com.commerce.auth.entity.RefreshToken;
import com.commerce.auth.entity.Role;
import com.commerce.auth.entity.User;
import com.commerce.auth.exception.BadRequestException;
import com.commerce.auth.exception.ConflictException;
import com.commerce.auth.exception.UnauthorizedException;
import com.commerce.auth.notification.VerificationEmailRequested;
import org.springframework.context.ApplicationEventPublisher;
import com.commerce.auth.repository.RefreshTokenRepository;
import com.commerce.auth.repository.RoleRepository;
import com.commerce.auth.repository.UserRepository;
import com.commerce.auth.security.jwt.JwtService;
import com.commerce.auth.service.AuthService;
import com.commerce.auth.service.EmailVerificationService;
import com.commerce.auth.service.RefreshTokenService;
import com.commerce.auth.utils.EmailNormalizer;
import com.commerce.auth.utils.RequestUtils;
import com.commerce.auth.utils.TokenHasher;
import io.jsonwebtoken.JwtException;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import jakarta.servlet.http.HttpServletRequest;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;


@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {


    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;
    private final EmailVerificationService emailVerificationService;
    private final ApplicationEventPublisher eventPublisher;


    private void validateRegisterRequest(
            RegisterRequest request,
            String normalizedEmail
    ) {

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new ConflictException(
                    "Email already registered"
            );
        }

        if (userRepository.existsByUsername(request.username())) {
            throw new ConflictException(
                    "Username already registered"
            );
        }
    }

    @Override
    @Transactional
    public RegisterResponse register(RegisterRequest request) {

        // 1. Normalisasi email
        String normalizedEmail =
                EmailNormalizer.normalize(request.email());

        // 2. Validasi duplicate email dan username
        validateRegisterRequest(request, normalizedEmail);

        // 3. Hash password
        String hashedPassword =
                passwordEncoder.encode(request.password());

        // 4. Role ditentukan oleh backend
        Role role = roleRepository
                .findByName(RoleName.USER)
                .orElseThrow(() ->
                        new IllegalStateException(
                                "Default USER role is not configured"
                        )
                );

        // 5. Build user
        User user = User.builder()
                .username(request.username())
                .email(normalizedEmail)
                .password(hashedPassword)
                .tokenVersion(0)
                .enabled(false)
                .emailVerified(false)
                .accountStatus(AccountStatus.PENDING_VERIFICATION)
                .build();

        // 6. Assign default role
        user.getRoles().add(role);

        // 7. Persist user
        User savedUser = userRepository.save(user);

        // Create the raw verification token and persist its hash in this
        // registration transaction. Only Auth Service owns this token.
        // The delivery step will be wired after the DB transaction commits.
        String rawVerificationToken = emailVerificationService.createVerificationToken(savedUser);
        // The event is consumed only AFTER_COMMIT. Never publish the raw token to logs.
        eventPublisher.publishEvent(new VerificationEmailRequested(
                savedUser.getId(), savedUser.getEmail(), savedUser.getUsername(), rawVerificationToken));

        // 8. Response
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

        String normalizedEmail =
                EmailNormalizer.normalize(request.email());

        User user =
                userRepository.findByEmail(normalizedEmail)
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

        if (!user.isAccountActive()) {
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



    @Override
    @Transactional
    public RefreshTokenResponse refreshToken(
            RefreshTokenRequest request,
            HttpServletRequest httpRequest
    ) {

        // 1. Ambil refresh token dari request
        String oldRefreshToken = request.refreshToken();

        // 2. Validasi refresh token pada database
        RefreshToken storedToken =
                refreshTokenService.validate(oldRefreshToken);

        // 3. Ambil pemilik refresh token
        User user = storedToken.getUser();

        // 4. Validasi status akun terkini
        if (!user.isAccountActive()) {
            throw new UnauthorizedException(
                    "Invalid refresh token"
            );
        }

        // 5. Validasi JWT refresh token
        boolean validRefreshToken;

        try {
            validRefreshToken = jwtService.isRefreshTokenValid(
                    oldRefreshToken,
                    user
            );
        } catch (JwtException | IllegalArgumentException ex) {
            throw new UnauthorizedException(
                    "Invalid refresh token"
            );
        }

        if (!validRefreshToken) {
            throw new UnauthorizedException(
                    "Invalid refresh token"
            );
        }

        // 6. Catat penggunaan refresh token lama
        storedToken.setLastUsedAt(LocalDateTime.now());

        // 7. Revoke token lama
        refreshTokenService.revoke(storedToken);

        // 8. Generate access dan refresh token baru
        String newAccessToken =
                jwtService.generateAccessToken(user);

        String newRefreshToken =
                jwtService.generateRefreshToken(user);

        // 9. Ambil informasi request
        String deviceInfo =
                RequestUtils.getDeviceInfo(httpRequest);

        String ipAddress =
                RequestUtils.getClientIp(httpRequest);

        // 10. Simpan refresh token baru
        refreshTokenService.create(
                user,
                newRefreshToken,
                deviceInfo,
                ipAddress
        );

        // 11. Response
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

        String username = authentication.getName();

        String tokenHash =
                TokenHasher.sha256(request.refreshToken());

        // 1. Cari refresh token
        RefreshToken storedToken = refreshTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() ->
                        new UnauthorizedException(
                                "Invalid refresh token"
                        )
                );

        // 2. Pastikan token milik user yang sedang login
        if (!storedToken.getUser()
                .getUsername()
                .equals(username)) {

            throw new UnauthorizedException(
                    "Invalid refresh token"
            );
        }

        // 3. Revoke refresh token
        refreshTokenService.revoke(storedToken);
    }


    @Override
    @Transactional
    public void logoutAll(Authentication authentication) {

        // 1. Identify authenticated user
        String username = authentication.getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new UnauthorizedException(
                                "User not found"
                        )
                );

        UUID userId = user.getId();

        // 2. Invalidate all previously issued JWTs
        int updatedRows =
                userRepository.incrementTokenVersion(userId);

        if (updatedRows != 1) {
            throw new IllegalStateException(
                    "Failed to invalidate user sessions"
            );
        }

        // 3. Revoke persisted refresh tokens
        refreshTokenRepository.revokeAllActiveByUserId(userId);
    }


}
