package com.commerce.auth.notification;

/** DTO matching Notification Service's internal HTTP contract. */
public record VerificationEmailPayload(
        String recipientEmail,
        String recipientName,
        String verificationUrl,
        long expiresInHours
) {
    @Override
    public String toString() {
        return "VerificationEmailPayload[redacted]";
    }
}
