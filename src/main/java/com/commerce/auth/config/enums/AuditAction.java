package com.commerce.auth.config.enums;

/*
@Author Didot
Created on 09/10/2026
@Last Modified on 09/10/2026 22:52
Version 1.0
*/

public enum AuditAction {

    // Registration
    USER_REGISTERED,

    // Email verification
    EMAIL_VERIFICATION_SUCCESS,
    EMAIL_VERIFICATION_FAILED,

    // Authentication
    LOGIN_SUCCESS,
    LOGIN_FAILED,

    // Session management
    TOKEN_REFRESHED,
    TOKEN_REFRESH_FAILED,
    USER_LOGOUT,
    ALL_SESSIONS_REVOKED,

    // User administration
    USER_SUSPENDED,
    USER_REACTIVATED,

    // Authorization
    ACCESS_DENIED
}
