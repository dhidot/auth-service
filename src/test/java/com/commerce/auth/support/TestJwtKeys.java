package com.commerce.auth.support;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/**
 * RSA keys generated in memory for tests, so no private key is ever
 * committed. One shared key per JVM keeps Spring's test-context cache
 * effective.
 */
public final class TestJwtKeys {

    private static final KeyPair SHARED = generate(2048);

    private TestJwtKeys() {
    }

    public static KeyPair shared() {
        return SHARED;
    }

    public static KeyPair generate(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** PKCS#8 PEM, exactly what `openssl genpkey` produces. */
    public static String pem(KeyPair keyPair) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes())
                .encodeToString(keyPair.getPrivate().getEncoded());
        return "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n";
    }
}
