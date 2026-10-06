package com.commerce.auth.event;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 22:18
Version 1.0
*/

import com.commerce.auth.config.enums.EventType;

import java.time.LocalDateTime;
import java.util.UUID;

public record UserRegisteredEvent(

        UUID eventId,

        Integer version,

        EventType eventType,

        LocalDateTime occurredAt,

        UUID userId,

        String username,

        String email,

        UUID verificationToken

) {
}