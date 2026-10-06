package com.commerce.auth.service;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 22:02
Version 1.0
*/

import com.commerce.auth.entity.EmailVerificationToken;
import com.commerce.auth.entity.User;

import java.util.UUID;

public interface EmailVerificationTokenService {

    EmailVerificationToken create(User user);

    void verify(UUID token);

    void resend(User user);

}