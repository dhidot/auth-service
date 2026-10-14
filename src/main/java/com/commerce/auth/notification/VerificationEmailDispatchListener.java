package com.commerce.auth.notification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
@ConditionalOnProperty(prefix = "careertrack.notification", name = "enabled", havingValue = "true", matchIfMissing = false)
public final class VerificationEmailDispatchListener {

    private static final Logger LOG = LoggerFactory.getLogger(VerificationEmailDispatchListener.class);
    private final VerificationNotificationClient notificationClient;

    public VerificationEmailDispatchListener(VerificationNotificationClient notificationClient) {
        this.notificationClient = notificationClient;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void onVerificationEmailRequested(VerificationEmailRequested event) {
        try {
            notificationClient.send(event.email(), event.username(), event.rawToken());
        } catch (RuntimeException ex) {
            // Account/token have already committed. Avoid changing HTTP 201 to 500.
            // Do NOT log the exception, URLs, headers, email address, or raw token.
            LOG.warn("Verification email delivery failed for userId={}; resend will be required", event.userId());
        }
    }
}
