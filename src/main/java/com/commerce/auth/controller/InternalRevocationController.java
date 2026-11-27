package com.commerce.auth.controller;

import com.commerce.auth.entity.TokenRevocation;
import com.commerce.auth.service.TokenRevocationService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Snapshot of all active token revocations for the gateway to poll
 * (ADR 0001, stage C2).
 *
 * <p>Internal only: neither Caddy nor the gateway routes {@code /internal/**}.
 * Requires {@code X-Internal-Api-Key} = {@code REVOCATIONS_INTERNAL_API_KEY}
 * (compared in constant time). While that key is not configured the
 * endpoint answers 404, so this version can be deployed before the
 * gateway uses it.
 *
 * <p>Always the full active list rather than "changes since a cursor":
 * database sequences can commit out of order, so a cursor can silently
 * skip an entry. Entries live one access-token lifetime, so the list is
 * small.
 */
@RestController
public class InternalRevocationController {

    static final String API_KEY_HEADER = "X-Internal-Api-Key";
    static final int MIN_KEY_LENGTH = 32;

    private final TokenRevocationService revocationService;
    private final Clock clock;
    private final byte[] apiKey;

    public InternalRevocationController(
            TokenRevocationService revocationService,
            Clock clock,
            @Value("${careertrack.revocations.internal-api-key:}") String apiKey
    ) {
        this.revocationService = revocationService;
        this.clock = clock;

        String key = apiKey == null ? "" : apiKey.trim();
        if (!key.isEmpty() && key.length() < MIN_KEY_LENGTH) {
            throw new IllegalStateException(
                    "REVOCATIONS_INTERNAL_API_KEY must be at least " + MIN_KEY_LENGTH
                            + " characters, or empty to disable /internal/revocations");
        }
        this.apiKey = key.isEmpty() ? null : key.getBytes(StandardCharsets.UTF_8);
    }

    @GetMapping(value = "/internal/revocations", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> revocations(
            @RequestHeader(value = API_KEY_HEADER, required = false) String presentedKey
    ) {
        if (apiKey == null) {
            return ResponseEntity.notFound().build();
        }
        if (presentedKey == null
                || !MessageDigest.isEqual(apiKey, presentedKey.getBytes(StandardCharsets.UTF_8))) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        List<Map<String, Object>> entries = revocationService.activeRevocations().stream()
                .map(InternalRevocationController::toJson)
                .toList();

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("serverTime", clock.instant().getEpochSecond());
        body.put("revocations", entries);

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(body);
    }

    /** Epoch seconds, comparable directly with JWT iat/exp. */
    private static Map<String, Object> toJson(TokenRevocation r) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("type", r.getType().name());
        json.put("sub", r.getUserId().toString());
        if (r.getType() == TokenRevocation.Type.SESSION) {
            json.put("sid", r.getSessionId().toString());
        } else {
            json.put("notBefore", r.getNotBefore().getEpochSecond());
        }
        json.put("expiresAt", r.getExpiresAt().getEpochSecond());
        return json;
    }
}
