package com.commerce.auth.config.enums;

/*
@Author Didot
Created on 26/07/2026
@Last Modified on 26/07/2026 20:35
Version 1.0
*/

public enum PermissionName {

    // User administration
    ADMIN_USER_READ,
    ADMIN_USER_UPDATE_STATUS,

    // Session management
    ADMIN_SESSION_REVOKE,

    // System monitoring
    ADMIN_DASHBOARD_READ,

    // Audit trail
    ADMIN_AUDIT_READ,

    // Role visibility
    ADMIN_ROLE_READ,

    // Integration monitoring
    ADMIN_INTEGRATION_LOG_READ
}
