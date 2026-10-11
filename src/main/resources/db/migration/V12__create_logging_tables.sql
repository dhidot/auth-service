
-- ============================================================
-- V12: CareerTrack Logging Infrastructure
--
-- 1. Activity Audit Log
-- 2. Service Integration Log
--
-- Supports HTTP, RabbitMQ, gRPC and future transports.
-- ============================================================


-- ============================================================
-- 1. ACTIVITY AUDIT LOG
-- ============================================================

CREATE TABLE audit_events (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    actor_user_id UUID,

    action VARCHAR(100) NOT NULL,

    outcome VARCHAR(20) NOT NULL,

    resource_type VARCHAR(100),

    resource_id VARCHAR(100),

    correlation_id VARCHAR(100),

    ip_address VARCHAR(50),

    user_agent VARCHAR(500),

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_audit_events_outcome
        CHECK (
            outcome IN (
                'SUCCESS',
                'FAILURE',
                'DENIED'
            )
        )
);

CREATE INDEX idx_audit_events_created_at
    ON audit_events (created_at DESC);

CREATE INDEX idx_audit_events_actor_created
    ON audit_events (actor_user_id, created_at DESC);

CREATE INDEX idx_audit_events_action_created
    ON audit_events (action, created_at DESC);

CREATE INDEX idx_audit_events_correlation
    ON audit_events (correlation_id);



-- ============================================================
-- 2. SERVICE INTEGRATION LOG
-- ============================================================

CREATE TABLE integration_logs (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Distributed tracing
    correlation_id VARCHAR(100),
    trace_id VARCHAR(100),

    -- Service identification
    source_service VARCHAR(100) NOT NULL,
    target_service VARCHAR(150) NOT NULL,

    -- Communication type
    transport VARCHAR(30) NOT NULL,
    direction VARCHAR(20) NOT NULL DEFAULT 'OUTBOUND',

    -- Business or technical operation
    operation VARCHAR(150),

    -- HTTP request information
    http_method VARCHAR(10),
    target_url VARCHAR(2048),

    -- HTTP response information
    http_status INTEGER,

    -- Safe, redacted HTTP headers
    request_headers JSONB,
    response_headers JSONB,

    -- Safe, redacted request/response bodies
    request_body TEXT,
    response_body TEXT,

    request_content_type VARCHAR(150),
    response_content_type VARCHAR(150),

    request_body_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    response_body_truncated BOOLEAN NOT NULL DEFAULT FALSE,

    -- Message broker information
    event_id VARCHAR(100),
    exchange_name VARCHAR(150),
    routing_key VARCHAR(200),

    -- Execution status
    status VARCHAR(30) NOT NULL,

    attempt_number INTEGER NOT NULL DEFAULT 1,

    -- Performance
    duration_ms BIGINT,

    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,

    -- Error information
    error_code VARCHAR(100),
    error_message VARCHAR(1000),

    -- Extension fields
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Record creation
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_integration_transport
        CHECK (
            transport IN (
                'HTTP',
                'RABBITMQ',
                'GRPC',
                'OTHER'
            )
        ),

    CONSTRAINT chk_integration_direction
        CHECK (
            direction IN (
                'INBOUND',
                'OUTBOUND'
            )
        ),

    CONSTRAINT chk_integration_status
        CHECK (
            status IN (
                'STARTED',
                'SUCCESS',
                'FAILED',
                'TIMEOUT',
                'RETRYING',
                'PUBLISHED',
                'ACKNOWLEDGED'
            )
        ),

    CONSTRAINT chk_integration_http_status
        CHECK (
            http_status IS NULL
            OR http_status BETWEEN 100 AND 599
        ),

    CONSTRAINT chk_integration_attempt
        CHECK (attempt_number >= 1),

    CONSTRAINT chk_integration_duration
        CHECK (
            duration_ms IS NULL
            OR duration_ms >= 0
        )
);


-- ============================================================
-- 3. INTEGRATION LOG INDEXES
-- ============================================================

-- Latest integration requests
CREATE INDEX idx_integration_logs_created
    ON integration_logs (created_at DESC);

-- Search all calls under the same correlation ID
CREATE INDEX idx_integration_logs_correlation
    ON integration_logs (correlation_id);

-- Filter by destination service
CREATE INDEX idx_integration_logs_target_created
    ON integration_logs (target_service, created_at DESC);

-- Filter by execution status
CREATE INDEX idx_integration_logs_status_created
    ON integration_logs (status, created_at DESC);

-- Distributed tracing
CREATE INDEX idx_integration_logs_trace
    ON integration_logs (trace_id);

-- Message tracking
CREATE INDEX idx_integration_logs_event
    ON integration_logs (event_id);
