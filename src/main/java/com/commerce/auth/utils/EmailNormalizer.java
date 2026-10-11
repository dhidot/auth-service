package com.commerce.auth.utils;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 17:52
Version 1.0
*/

import java.util.Locale;
import java.util.Objects;

public final class EmailNormalizer {

    private EmailNormalizer() {
    }

    public static String normalize(String email) {
        return Objects.requireNonNull(email, "Email cannot be null")
                .trim()
                .toLowerCase(Locale.ROOT);
    }
}