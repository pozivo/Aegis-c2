-- Aegis C2 M1 schema. Applied once on a fresh local PostgreSQL database.
-- Production upgrades will use a versioned migration runner and dedicated roles.
BEGIN;

CREATE TABLE engagements (
    id text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    name text NOT NULL CHECK (length(trim(name)) BETWEEN 1 AND 255),
    allowed_cidrs cidr[] NOT NULL CHECK (cardinality(allowed_cidrs) BETWEEN 1 AND 256),
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);

CREATE TABLE enrollment_tokens (
    engagement_id text PRIMARY KEY REFERENCES engagements(id) ON DELETE RESTRICT,
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at),
    CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE TABLE agents (
    id text PRIMARY KEY CHECK (id ~ '^[0-9a-f]{32}$'),
    engagement_id text NOT NULL REFERENCES engagements(id) ON DELETE RESTRICT,
    hostname text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 253),
    os text NOT NULL CHECK (length(os) BETWEEN 1 AND 64),
    architecture text NOT NULL CHECK (length(architecture) BETWEEN 1 AND 64),
    labels jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(labels) = 'object'),
    enrolled_at timestamptz NOT NULL DEFAULT now(),
    last_seen timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX agents_engagement_idx ON agents(engagement_id);

CREATE TABLE audit_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    id text NOT NULL UNIQUE CHECK (id ~ '^[0-9a-f]{32}$'),
    event_time timestamptz NOT NULL,
    action text NOT NULL,
    subject_id text NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
    prev_hash text NOT NULL CHECK (prev_hash = '' OR prev_hash ~ '^[0-9a-f]{64}$'),
    hash text NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE FUNCTION reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit events are append-only';
END;
$$;

CREATE TRIGGER audit_events_immutable
    BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

COMMIT;
