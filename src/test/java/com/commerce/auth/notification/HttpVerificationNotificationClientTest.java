package com.commerce.auth.notification;

import com.commerce.auth.utils.VerificationTokenUtils;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class HttpVerificationNotificationClientTest {

    private static final String API_KEY = "test-only-internal-api-key-32-character-minimum";
    private HttpServer server;
    private final AtomicReference<String> receivedBody = new AtomicReference<>();
    private final AtomicReference<String> receivedKey = new AtomicReference<>();
    private int responseStatus;

    @BeforeEach
    void setUp() throws Exception {
        responseStatus = 204;
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/internal/notifications/email-verification", exchange -> {
            receivedKey.set(exchange.getRequestHeaders().getFirst("X-Internal-Api-Key"));
            receivedBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(responseStatus, -1);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void tearDown() {
        if (server != null) server.stop(0);
    }

    private HttpVerificationNotificationClient client() {
        return new HttpVerificationNotificationClient(
                RestClient.builder(),
                "http://127.0.0.1:" + server.getAddress().getPort(),
                API_KEY,
                "http://localhost:3000/verify-email");
    }

    @Test
    void sendsAuthenticatedVerificationRequestWithFragmentLink() {
        String rawToken = VerificationTokenUtils.generateToken();
        client().send("user@example.test", "Career User", rawToken);
        assertEquals(API_KEY, receivedKey.get());
        assertNotNull(receivedBody.get());
        assertTrue(receivedBody.get().contains("user@example.test"));
        assertTrue(receivedBody.get().contains("#token=" + rawToken));
        assertTrue(receivedBody.get().contains("\"expiresInHours\":24"));
    }

    @Test
    void propagatesHttp503ToDeliveryListener() {
        responseStatus = 503;
        assertThrows(RestClientResponseException.class,
                () -> client().send("user@example.test", "Career User", VerificationTokenUtils.generateToken()));
    }

    @Test
    void rejectsMissingApiKeyAtStartup() {
        assertThrows(IllegalStateException.class, () -> new HttpVerificationNotificationClient(
                RestClient.builder(), "http://localhost:8082", "short", "http://localhost:3000/verify-email"));
    }

    @Test
    void rejectsInsecurePublicVerificationUrl() {
        assertThrows(IllegalStateException.class, () -> new HttpVerificationNotificationClient(
                RestClient.builder(), "http://localhost:8082", API_KEY, "http://example.com/verify-email"));
    }
}
