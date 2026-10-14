package com.commerce.auth.notification;

public interface VerificationNotificationClient {
    void send(String email, String username, String rawToken);
}
