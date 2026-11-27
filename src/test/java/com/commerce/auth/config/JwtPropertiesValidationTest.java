package com.commerce.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.StandardEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The application refuses to start with missing or invalid JWT settings
 * instead of failing on the first login. The private key's content is
 * checked by JwtKeys (see JwtKeysTest); here only its presence.
 */
class JwtPropertiesValidationTest {

    private static final String VALID_SECRET =
            "0123456789abcdef0123456789abcdef"; // 32 ASCII bytes

    // Only presence is validated here; parsing is covered by JwtKeysTest.
    private static final String PRIVATE_KEY = "jwt.private-key=placeholder-not-parsed-in-this-test";

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(JwtProperties.class)
    static class Config {
    }

    // Remove OS env and JVM system properties so JWT_* variables set
    // on the machine/CI (relaxed binding maps them to jwt.*) cannot leak
    // into these cases.
    private final ApplicationContextRunner runner =
            new ApplicationContextRunner()
                    .withInitializer(context -> {
                        var sources = context.getEnvironment()
                                .getPropertySources();
                        sources.remove(StandardEnvironment
                                .SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
                        sources.remove(StandardEnvironment
                                .SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
                    })
                    .withUserConfiguration(Config.class)
                    .withPropertyValues(
                            "jwt.access-token-expiration=900000",
                            "jwt.refresh-token-expiration=604800000"
                    );

    private static String rootMessage(Throwable failure) {
        StringBuilder messages = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            messages.append(t.getMessage()).append('\n');
        }
        return messages.toString();
    }

    // ---------------------------------------------------------------
    // Private key (required)
    // ---------------------------------------------------------------

    @Test
    void startsWithAPrivateKeyAndNoLegacySecret() {
        runner.withPropertyValues(PRIVATE_KEY)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    JwtProperties properties = context.getBean(JwtProperties.class);
                    assertThat(properties.hasLegacySecret()).isFalse();
                    assertThat(properties.getIssuer()).isEqualTo("careertrack-auth");
                    assertThat(properties.getAudience()).isEqualTo("careertrack-api");
                });
    }

    @Test
    void failsWhenPrivateKeyIsMissing() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootMessage(context.getStartupFailure()))
                    .contains("JWT_PRIVATE_KEY");
        });
    }

    @Test
    void failsWhenPrivateKeyIsEmpty() {
        // What application.properties produces when JWT_PRIVATE_KEY is unset.
        runner.withPropertyValues("jwt.private-key=")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void failsWhenPrivateKeyPlaceholderIsUnresolved() {
        runner.withPropertyValues("jwt.private-key=${JWT_PRIVATE_KEY}")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure()))
                            .contains("unresolved placeholder");
                });
    }

    // ---------------------------------------------------------------
    // Legacy HS256 secret (optional, transition only)
    // ---------------------------------------------------------------

    @Test
    void acceptsA32ByteLegacySecret() {
        runner.withPropertyValues(PRIVATE_KEY, "jwt.secret=" + VALID_SECRET)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(JwtProperties.class).hasLegacySecret()).isTrue();
                });
    }

    @Test
    void treatsABlankLegacySecretAsDisabled() {
        runner.withPropertyValues(PRIVATE_KEY, "jwt.secret=   ")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(JwtProperties.class).hasLegacySecret()).isFalse();
                });
    }

    @Test
    void failsWhenLegacySecretPlaceholderIsUnresolved() {
        runner.withPropertyValues(PRIVATE_KEY, "jwt.secret=${JWT_SECRET}")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure()))
                            .contains("unresolved placeholder");
                });
    }

    @Test
    void failsWhenLegacySecretIsShorterThan32Bytes() {
        runner.withPropertyValues(PRIVATE_KEY, "jwt.secret=" + VALID_SECRET.substring(1))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure()))
                            .contains("at least 32 bytes");
                });
    }

    @Test
    void measuresLegacySecretInUtf8BytesNotCharacters() {
        // 11 characters x 3 bytes = 33 bytes: accepted.
        runner.withPropertyValues(PRIVATE_KEY, "jwt.secret=" + "€".repeat(11))
                .run(context -> assertThat(context).hasNotFailed());
    }

    // ---------------------------------------------------------------
    // Other settings
    // ---------------------------------------------------------------

    @Test
    void failsWhenExpirationIsNotPositive() {
        runner.withPropertyValues(PRIVATE_KEY, "jwt.access-token-expiration=0")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void failsWhenIssuerIsBlank() {
        runner.withPropertyValues(PRIVATE_KEY, "jwt.issuer= ")
                .run(context -> assertThat(context).hasFailed());
    }
}
