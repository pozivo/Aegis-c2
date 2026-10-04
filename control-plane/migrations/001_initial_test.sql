\set ON_ERROR_STOP on

BEGIN;
INSERT INTO engagements (id, name, allowed_cidrs, expires_at)
VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'migration smoke test', ARRAY['127.0.0.0/8'::cidr], now() + interval '1 day');

INSERT INTO enrollment_tokens (engagement_id, token_digest, expires_at)
VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', decode(repeat('a', 64), 'hex'), now() + interval '1 day');

INSERT INTO agents (id, engagement_id, hostname, os, architecture)
VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'lab-host', 'linux', 'amd64');

INSERT INTO audit_events (id, event_time, action, subject_id, prev_hash, hash)
VALUES ('cccccccccccccccccccccccccccccccc', now(), 'engagement.created', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', '', repeat('d', 64));

DO $$
BEGIN
    IF (SELECT count(*) FROM engagements) <> 1 OR
       (SELECT count(*) FROM agents) <> 1 OR
       (SELECT count(*) FROM audit_events) <> 1 THEN
        RAISE EXCEPTION 'migration smoke test did not persist expected rows';
    END IF;

    BEGIN
        UPDATE audit_events SET action = 'tampered' WHERE sequence = 1;
        RAISE EXCEPTION 'audit update unexpectedly succeeded';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM <> 'audit events are append-only' THEN
            RAISE;
        END IF;
    END;

    BEGIN
        DELETE FROM audit_events WHERE sequence = 1;
        RAISE EXCEPTION 'audit delete unexpectedly succeeded';
    EXCEPTION WHEN raise_exception THEN
        IF SQLERRM <> 'audit events are append-only' THEN
            RAISE;
        END IF;
    END;
END;
$$;
ROLLBACK;
