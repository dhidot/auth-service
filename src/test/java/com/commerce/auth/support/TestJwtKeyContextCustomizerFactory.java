package com.commerce.auth.support;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.test.context.ContextConfigurationAttributes;
import org.springframework.test.context.ContextCustomizer;
import org.springframework.test.context.ContextCustomizerFactory;
import org.springframework.test.context.MergedContextConfiguration;

import java.util.List;
import java.util.Map;

/**
 * Supplies {@code jwt.private-key} to every Spring test context
 * (registered in META-INF/spring.factories), so tests never depend on a
 * JWT_PRIVATE_KEY on the developer's machine or in CI.
 */
public class TestJwtKeyContextCustomizerFactory implements ContextCustomizerFactory {

    @Override
    public ContextCustomizer createContextCustomizer(
            Class<?> testClass,
            List<ContextConfigurationAttributes> configAttributes
    ) {
        return Customizer.INSTANCE;
    }

    private static final class Customizer implements ContextCustomizer {

        static final Customizer INSTANCE = new Customizer();

        @Override
        public void customizeContext(
                ConfigurableApplicationContext context,
                MergedContextConfiguration mergedConfig
        ) {
            // First: application.properties resolves jwt.private-key to ""
            // when JWT_PRIVATE_KEY is unset, which would otherwise win.
            context.getEnvironment().getPropertySources().addFirst(
                    new MapPropertySource(
                            "testJwtPrivateKey",
                            Map.of("jwt.private-key", TestJwtKeys.pem(TestJwtKeys.shared()))
                    )
            );
        }

        // Same customizer for every test class: keeps context caching.
        @Override
        public boolean equals(Object other) {
            return other instanceof Customizer;
        }

        @Override
        public int hashCode() {
            return Customizer.class.hashCode();
        }
    }
}
