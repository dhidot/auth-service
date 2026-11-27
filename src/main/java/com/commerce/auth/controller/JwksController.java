package com.commerce.auth.controller;

import com.commerce.auth.security.jwt.JwtKeys;
import lombok.RequiredArgsConstructor;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

/**
 * Public signing keys (RFC 7517 JWK Set) so other services can verify
 * access tokens without holding the private key (ADR 0001).
 *
 * <p>Reachable only on the internal Docker network: neither Caddy nor
 * the gateway routes {@code /.well-known/**}. Contains no secrets.
 */
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final JwtKeys jwtKeys;

    @GetMapping(
            value = "/.well-known/jwks.json",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(jwtKeys.jwks());
    }
}
