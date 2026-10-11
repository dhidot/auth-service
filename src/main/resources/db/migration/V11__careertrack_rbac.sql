
-- ============================================================
-- V11: CareerTrack Role-Based Access Control
-- Roles: USER, ADMIN
-- ============================================================


-- ============================================================
-- 1. Validate existing role assignments
-- ============================================================

-- Prevent migration when users still have legacy roles.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM user_roles ur
        JOIN roles r ON r.id = ur.role_id
        WHERE r.name NOT IN ('USER', 'ADMIN')
    ) THEN
        RAISE EXCEPTION
            'Legacy role assignments must be resolved before V11';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM user_roles
        GROUP BY user_id
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION
            'Users with multiple roles must be resolved before V11';
    END IF;
END $$;


-- ============================================================
-- 2. Remove legacy role-permission mappings
-- ============================================================

DELETE FROM role_permissions;


-- ============================================================
-- 3. Remove legacy roles
-- ============================================================

DELETE FROM roles
WHERE name NOT IN ('USER', 'ADMIN');


-- ============================================================
-- 4. Remove legacy permissions
-- ============================================================

DELETE FROM permissions
WHERE name NOT IN (
    'ADMIN_USER_READ',
    'ADMIN_USER_UPDATE_STATUS',
    'ADMIN_SESSION_REVOKE',
    'ADMIN_DASHBOARD_READ',
    'ADMIN_AUDIT_READ',
    'ADMIN_ROLE_READ',
    'ADMIN_INTEGRATION_LOG_READ'
);


-- ============================================================
-- 5. Seed CareerTrack roles
-- FIX: Include created_at and updated_at
-- ============================================================

INSERT INTO roles (
    id,
    name,
    description,
    created_at,
    updated_at
)
VALUES
    (
        gen_random_uuid(),
        'USER',
        'CareerTrack application user',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        gen_random_uuid(),
        'ADMIN',
        'CareerTrack CMS administrator',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    )
ON CONFLICT (name) DO NOTHING;


-- ============================================================
-- 6. Seed CareerTrack CMS permissions
-- FIX: Include created_at and updated_at
-- ============================================================

INSERT INTO permissions (
    id,
    name,
    description,
    created_at,
    updated_at
)
VALUES
    (
        gen_random_uuid(),
        'ADMIN_USER_READ',
        'View administrative user information',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        gen_random_uuid(),
        'ADMIN_USER_UPDATE_STATUS',
        'Suspend or reactivate users',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        gen_random_uuid(),
        'ADMIN_SESSION_REVOKE',
        'Revoke user sessions',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        gen_random_uuid(),
        'ADMIN_DASHBOARD_READ',
        'View administrative dashboard',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        gen_random_uuid(),
        'ADMIN_AUDIT_READ',
        'View activity audit logs',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        gen_random_uuid(),
        'ADMIN_ROLE_READ',
        'View role and permission information',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        gen_random_uuid(),
        'ADMIN_INTEGRATION_LOG_READ',
        'View interservice integration logs',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    )
ON CONFLICT (name) DO NOTHING;


-- ============================================================
-- 7. Assign CMS permissions to ADMIN
-- ============================================================

INSERT INTO role_permissions (
    role_id,
    permission_id
)
SELECT
    r.id,
    p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.name = 'ADMIN'
  AND p.name IN (
      'ADMIN_USER_READ',
      'ADMIN_USER_UPDATE_STATUS',
      'ADMIN_SESSION_REVOKE',
      'ADMIN_DASHBOARD_READ',
      'ADMIN_AUDIT_READ',
      'ADMIN_ROLE_READ',
      'ADMIN_INTEGRATION_LOG_READ'
  )
ON CONFLICT DO NOTHING;


-- ============================================================
-- 8. Enforce one role per user
-- ============================================================

CREATE UNIQUE INDEX ux_user_roles_one_role_per_user
ON user_roles (user_id);
