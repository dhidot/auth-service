package com.commerce.auth.service;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 19:48
Version 1.0
*/

import com.commerce.auth.entity.User;

public interface EmailVerificationService {

    String createVerificationToken(User user);

    void verifyEmail(String rawToken);
}