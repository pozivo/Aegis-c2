-- Existing agents must re-enroll after this upgrade to receive a heartbeat token.
-- A null digest prevents legacy unauthenticated heartbeats.
BEGIN;
ALTER TABLE agents ADD COLUMN heartbeat_token_digest bytea
    CHECK (heartbeat_token_digest IS NULL OR octet_length(heartbeat_token_digest) = 32);
COMMIT;
