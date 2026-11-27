package com.commerce.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.time.Clock;

/**
 * Shared clock (replaceable in tests) and scheduling for housekeeping
 * jobs such as purging expired token revocations.
 */
@Configuration(proxyBeanMethods = false)
@EnableScheduling
public class TimeConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }
}
