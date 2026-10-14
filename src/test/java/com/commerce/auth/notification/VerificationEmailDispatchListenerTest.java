package com.commerce.auth.notification;

import org.junit.jupiter.api.Test;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import java.lang.reflect.Method;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class VerificationEmailDispatchListenerTest {

    private final VerificationNotificationClient client = mock(VerificationNotificationClient.class);
    private final VerificationEmailDispatchListener listener = new VerificationEmailDispatchListener(client);
    private final VerificationEmailRequested event = new VerificationEmailRequested(
            UUID.randomUUID(), "user@example.test", "Career User", "dummy-token-for-unit-test");

    @Test
    void sendsEmailWhenInvokedAfterCommit() {
        listener.onVerificationEmailRequested(event);
        verify(client).send(event.email(), event.username(), event.rawToken());
    }

    @Test
    void deliveryFailureMustNotPropagateAfterAccountCommit() {
        doThrow(new IllegalStateException("Sensitive error details"))
                .when(client).send(anyString(), anyString(), anyString());
        assertDoesNotThrow(() -> listener.onVerificationEmailRequested(event));
    }

    @Test
    void listenerRunsOnlyAfterDatabaseCommit() throws Exception {
        Method method = VerificationEmailDispatchListener.class.getMethod(
                "onVerificationEmailRequested", VerificationEmailRequested.class);
        TransactionalEventListener annotation = method.getAnnotation(TransactionalEventListener.class);
        assertNotNull(annotation);
        assertEquals(TransactionPhase.AFTER_COMMIT, annotation.phase());
    }
}
