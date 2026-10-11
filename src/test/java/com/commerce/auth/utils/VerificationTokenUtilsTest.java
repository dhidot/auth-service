package com.commerce.auth.utils;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 19:49
Version 1.0
*/
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class VerificationTokenUtilsTest {

    @Test
    void generateToken_shouldCreateUrlSafeToken() {

        String token = VerificationTokenUtils.generateToken();

        assertNotNull(token);

        assertEquals(43, token.length());

        assertTrue(token.matches("[A-Za-z0-9_-]+"));
    }

    @Test
    void generateToken_shouldGenerateDifferentTokens() {

        Set<String> tokens = new HashSet<>();

        for (int i = 0; i < 100; i++) {
            tokens.add(
                    VerificationTokenUtils.generateToken()
            );
        }

        assertEquals(100, tokens.size());
    }

    @Test
    void hashToken_shouldReturn64CharacterHexString() {

        String token = VerificationTokenUtils.generateToken();

        String hash = VerificationTokenUtils.hashToken(token);

        assertEquals(64, hash.length());
        assertTrue(hash.matches("[a-f0-9]{64}"));
        assertNotEquals(token, hash);
    }

    @Test
    void hashToken_whenSameToken_shouldProduceSameHash() {

        String token = VerificationTokenUtils.generateToken();

        assertEquals(
                VerificationTokenUtils.hashToken(token),
                VerificationTokenUtils.hashToken(token)
        );
    }
}