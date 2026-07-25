package com.commerce.auth.utils;

/*
@Author Didot
Created on 25/07/2026
@Last Modified on 25/07/2026 23:38
Version 1.0
*/

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class TokenHasher {

    private TokenHasher() {}

    public static String sha256(String value) {

        try {

            MessageDigest md =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash =
                    md.digest(value.getBytes(StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();

            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }

            return sb.toString();

        } catch (Exception e) {

            throw new RuntimeException(e);

        }

    }

}