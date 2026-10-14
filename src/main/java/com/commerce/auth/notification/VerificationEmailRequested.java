package com.commerce.auth.notification;

import java.util.UUID;

/** In-process event only: the raw token must never be serialized to logs or persisted. */
public record VerificationEmailRequested(
        UUID userId,
        String email,
        String username,
        String rawToken
) {
    // Java records normally include every field in toString(). Never print the raw token.
    @Override
    public String toString() {
        return "VerificationEmailRequested[userId=" + userId + "]";
    }
}
