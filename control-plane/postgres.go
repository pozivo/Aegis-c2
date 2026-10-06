package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/lib/pq"
)

// appendPostgresAudit must be called inside the same transaction as the change
// it records. The advisory lock serializes writers to the global hash chain.
func appendPostgresAudit(ctx context.Context, tx *sql.Tx, event auditEvent) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(475324)`); err != nil {
		return err
	}
	var previous string
	if err := tx.QueryRowContext(ctx, `SELECT hash FROM audit_events ORDER BY sequence DESC LIMIT 1`).Scan(&previous); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	event.PrevHash = previous
	event.Hash = auditHash(event)
	if event.Details == nil {
		event.Details = map[string]any{}
	}
	details, err := json.Marshal(event.Details)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events
		(id, event_time, action, subject_id, details, prev_hash, hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		event.ID, event.Time, event.Action, event.SubjectID, details, event.PrevHash, event.Hash)
	return err
}

func newPostgresHandler(db *sql.DB, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "database unavailable"})
			return
		}
		events, err := readPostgresAudit(ctx, db)
		if err != nil || !verifyAuditChain(events) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "audit integrity failure"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /v1/engagements", func(w http.ResponseWriter, r *http.Request) {
		var e engagement
		if decodeJSON(w, r, &e) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		current := now().UTC().Truncate(time.Microsecond)
		if err := validateEngagement(e, current); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		e.ID, e.CreatedAt = id(), current
		token := id()
		digest := sha256.Sum256([]byte(token))
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
			return
		}
		defer tx.Rollback()
		_, err = tx.ExecContext(r.Context(), `INSERT INTO engagements
			(id, name, allowed_cidrs, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)`,
			e.ID, e.Name, pq.Array(e.AllowedCIDRs), e.ExpiresAt, e.CreatedAt)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO enrollment_tokens
				(engagement_id, token_digest, expires_at, created_at) VALUES ($1, $2, $3, $4)`,
				e.ID, digest[:], e.ExpiresAt, current)
		}
		if err == nil {
			err = appendPostgresAudit(r.Context(), tx, auditEvent{ID: id(), Time: current, Action: "engagement.created", SubjectID: e.ID})
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "engagement transaction failed"})
			return
		}
		writeJSON(w, http.StatusCreated, engagementCreated{engagement: e, EnrollmentToken: token})
	})
	mux.HandleFunc("POST /v1/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		var a agent
		if decodeJSON(w, r, &a) != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if err := validateAgent(a); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		token, ok := bearerToken(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment token required"})
			return
		}
		current := now().UTC().Truncate(time.Microsecond)
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "database unavailable"})
			return
		}
		defer tx.Rollback()
		var digest []byte
		var expires time.Time
		var consumed sql.NullTime
		err = tx.QueryRowContext(r.Context(), `SELECT t.token_digest, t.expires_at, t.consumed_at
			FROM enrollment_tokens t JOIN engagements e ON e.id = t.engagement_id
			WHERE t.engagement_id = $1 AND e.expires_at > $2 FOR UPDATE OF t`,
			a.EngagementID, current).Scan(&digest, &expires, &consumed)
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "engagement unavailable"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "enrollment lookup failed"})
			return
		}
		var expected [sha256.Size]byte
		copy(expected[:], digest)
		if consumed.Valid || !expires.After(current) || !tokenMatches(token, expected) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid enrollment token"})
			return
		}
		a.ID, a.LastSeen = id(), current
		heartbeatToken := id()
		heartbeatDigest := sha256.Sum256([]byte(heartbeatToken))
		if a.Labels == nil {
			a.Labels = map[string]string{}
		}
		labels, err := json.Marshal(a.Labels)
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `INSERT INTO agents
				(id, engagement_id, hostname, os, architecture, labels, enrolled_at, last_seen, heartbeat_token_digest)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $8)`,
				a.ID, a.EngagementID, a.Hostname, a.OS, a.Architecture, labels, current, heartbeatDigest[:])
		}
		if err == nil {
			_, err = tx.ExecContext(r.Context(), `UPDATE enrollment_tokens SET consumed_at = $2 WHERE engagement_id = $1`, a.EngagementID, current)
		}
		if err == nil {
			err = appendPostgresAudit(r.Context(), tx, auditEvent{ID: id(), Time: current, Action: "agent.enrolled", SubjectID: a.ID, Details: map[string]any{"engagement_id": a.EngagementID}})
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "enrollment transaction failed"})
			return
		}
		writeJSON(w, http.StatusCreated, agentEnrolled{agent: a, HeartbeatToken: heartbeatToken})
	})
	mux.HandleFunc("POST /v1/agents/{agentID}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		current := now().UTC()
		token, present := bearerToken(r)
		if !present {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "heartbeat token required"})
			return
		}
		var digest []byte
		err := db.QueryRowContext(r.Context(), `SELECT heartbeat_token_digest FROM agents WHERE id = $1`, r.PathValue("agentID")).Scan(&digest)
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent unavailable"})
			return
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "heartbeat lookup failed"})
			return
		}
		var expected [sha256.Size]byte
		copy(expected[:], digest)
		if len(digest) != sha256.Size || !tokenMatches(token, expected) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid heartbeat token"})
			return
		}
		result, err := db.ExecContext(r.Context(), `UPDATE agents a SET last_seen = $2
			FROM engagements e WHERE a.id = $1 AND e.id = a.engagement_id AND e.expires_at > $2`,
			r.PathValue("agentID"), current)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "heartbeat failed"})
			return
		}
		count, err := result.RowsAffected()
		if err != nil || count == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "server_time": current})
	})
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, r *http.Request) {
		events, err := readPostgresAudit(r.Context(), db)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "audit unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, events)
	})
	return mux
}

func readPostgresAudit(ctx context.Context, db *sql.DB) ([]auditEvent, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, event_time, action, subject_id, details, prev_hash, hash
		FROM audit_events ORDER BY sequence`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	events := make([]auditEvent, 0)
	for rows.Next() {
		var event auditEvent
		var details []byte
		if err := rows.Scan(&event.ID, &event.Time, &event.Action, &event.SubjectID, &details, &event.PrevHash, &event.Hash); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(details, &event.Details); err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}
