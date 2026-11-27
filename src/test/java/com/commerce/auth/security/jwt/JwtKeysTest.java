package com.commerce.auth.security.jwt;

import com.commerce.auth.config.JwtProperties;
import com.commerce.auth.support.TestJwtKeys;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtKeysTest {

    private static JwtKeys keysFrom(String privateKey) {
        JwtProperties properties = new JwtProperties();
        properties.setPrivateKey(privateKey);
        return new JwtKeys(properties);
    }

    private static final String PEM = TestJwtKeys.pem(TestJwtKeys.shared());

    @Test
    void acceptsPkcs8Pem() {
        JwtKeys keys = keysFrom(PEM);

        assertThat(keys.publicKey().getModulus()).isEqualTo(keys.privateKey().getModulus());
        assertThat(keys.keyId()).isNotBlank();
    }

    @Test
    void acceptsBase64EncodedPemOnOneLine() {
        String oneLine = Base64.getEncoder().encodeToString(PEM.getBytes(StandardCharsets.UTF_8));

        assertThat(keysFrom(oneLine).keyId()).isEqualTo(keysFrom(PEM).keyId());
    }

    @Test
    void acceptsPemWithLiteralBackslashN() {
        String escaped = PEM.replace("\n", "\\n");

        assertThat(keysFrom(escaped).keyId()).isEqualTo(keysFrom(PEM).keyId());
    }

    @Test
    void keyIdIsStableForTheSameKeyAndDiffersForAnother() {
        String other = TestJwtKeys.pem(TestJwtKeys.generate(2048));

        assertThat(keysFrom(PEM).keyId()).isEqualTo(keysFrom(PEM).keyId());
        assertThat(keysFrom(other).keyId()).isNotEqualTo(keysFrom(PEM).keyId());
    }

    @Test
    @SuppressWarnings("unchecked")
    void jwksPublishesOnlyPublicParts() {
        JwtKeys keys = keysFrom(PEM);
        List<Map<String, Object>> jwks = (List<Map<String, Object>>) keys.jwks().get("keys");

        assertThat(jwks).hasSize(1);
        Map<String, Object> jwk = jwks.getFirst();
        assertThat(jwk).containsEntry("kty", "RSA")
                .containsEntry("alg", "RS256")
                .containsEntry("use", "sig")
                .containsEntry("kid", keys.keyId())
                .containsKeys("n", "e");
        // Private RSA parameters must never be published.
        assertThat(jwk).doesNotContainKeys("d", "p", "q", "dp", "dq", "qi");
    }

    @Test
    void rejectsMissingKey() {
        assertThatThrownBy(() -> keysFrom(null))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("JWT_PRIVATE_KEY");
        assertThatThrownBy(() -> keysFrom("  "))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsKeysShorterThan2048Bits() {
        assertThatThrownBy(() -> keysFrom(TestJwtKeys.pem(TestJwtKeys.generate(1024))))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("at least 2048");
    }

    @Test
    void rejectsPkcs1WithAHelpfulMessage() {
        String pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n";

        assertThatThrownBy(() -> keysFrom(pkcs1))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("openssl pkcs8");
    }

    @Test
    void rejectsNonRsaKeys() throws Exception {
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        KeyPair pair = ec.generateKeyPair();

        assertThatThrownBy(() -> keysFrom(TestJwtKeys.pem(pair)))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rejectsGarbageWithoutEchoingIt() {
        assertThatThrownBy(() -> keysFrom("-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageNotContaining("not-a-key");
    }
}
