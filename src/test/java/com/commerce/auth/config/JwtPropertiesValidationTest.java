package com.commerce.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.StandardEnvironment;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the application refuses to start with a missing,
 * unresolved or too-short JWT secret, instead of starting and
 * returning 500 on the first login.
 */
class JwtPropertiesValidationTest {

    private static final String VALID_SECRET =
            "0123456789abcdef0123456789abcdef"; // 32 ASCII bytes

    @Configuration(proxyBeanMethods = false)
    @EnableConfigurationProperties(JwtProperties.class)
    static class Config {
    }

    // Remove OS env and JVM system properties so a JWT_SECRET set
    // on the machine/CI (relaxed binding maps it to jwt.secret)
    // cannot leak into these cases.
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

    @Test
    void startsWithA32ByteSecret() {
        runner.withPropertyValues("jwt.secret=" + VALID_SECRET)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(JwtProperties.class)
                            .getSecret()).isEqualTo(VALID_SECRET);
                });
    }

    @Test
    void failsWhenSecretIsMissing() {
        runner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(rootMessage(context.getStartupFailure()))
                    .contains("secret")
                    .contains("JWT_SECRET");
        });
    }

    @Test
    void failsWhenSecretIsBlank() {
        runner.withPropertyValues("jwt.secret=   ")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void failsWhenPlaceholderIsUnresolved() {
        // Same value the binder produces when JWT_SECRET is not set.
        runner.withPropertyValues("jwt.secret=${JWT_SECRET}")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure()))
                            .contains("unresolved placeholder");
                });
    }

    @Test
    void failsWhenSecretIsShorterThan32Bytes() {
        runner.withPropertyValues("jwt.secret=" + VALID_SECRET.substring(1))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(rootMessage(context.getStartupFailure()))
                            .contains("at least 32 bytes");
                });
    }

    @Test
    void measuresLengthInUtf8BytesNotCharacters() {
        // 11 characters x 3 bytes = 33 bytes: accepted.
        runner.withPropertyValues("jwt.secret=" + "€".repeat(11))
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void failsWhenExpirationIsNotPositive() {
        runner.withPropertyValues(
                        "jwt.secret=" + VALID_SECRET,
                        "jwt.access-token-expiration=0"
                )
                .run(context -> assertThat(context).hasFailed());
    }
}
