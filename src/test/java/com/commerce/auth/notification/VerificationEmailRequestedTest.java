package com.commerce.auth.notification;

import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class VerificationEmailRequestedTest {
    @Test
    void doesNotExposeRawTokenThroughToString() {
        VerificationEmailRequested event = new VerificationEmailRequested(
                UUID.randomUUID(), "user@example.test", "user", "sensitive-raw-token");
        assertFalse(event.toString().contains("sensitive-raw-token"));
    }
}
