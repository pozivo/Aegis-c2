package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPostgresPersistsEnrollmentAcrossHandlers(t *testing.T) {
	url := os.Getenv("AEGIS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("AEGIS_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatal(err)
	}
	clock := time.Now().UTC()
	handler := newPostgresHandler(db, func() time.Time { return clock })
	response := request(t, handler, http.MethodPost, "/v1/engagements", map[string]any{
		"name": "ci-lab", "allowed_cidrs": []string{"127.0.0.0/8"},
		"expires_at": clock.Add(time.Hour),
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("engagement returned %d: %s", response.Code, response.Body.String())
	}
	var created engagementCreated
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	// A fresh handler represents a restarted API process against the same database.
	restarted := newPostgresHandler(db, func() time.Time { return clock })
	body := map[string]any{"engagement_id": created.ID, "hostname": "ci-host", "os": "linux", "architecture": "amd64"}
	enrolled := requestWithToken(t, restarted, http.MethodPost, "/v1/agents/enroll", body, created.EnrollmentToken)
	if enrolled.Code != http.StatusCreated {
		t.Fatalf("enrollment returned %d: %s", enrolled.Code, enrolled.Body.String())
	}
	var agentRecord agentEnrolled
	if err := json.NewDecoder(enrolled.Body).Decode(&agentRecord); err != nil {
		t.Fatal(err)
	}
	if response := requestWithToken(t, restarted, http.MethodPost, "/v1/agents/enroll", body, created.EnrollmentToken); response.Code != http.StatusUnauthorized {
		t.Fatalf("reused token returned %d", response.Code)
	}
	if response := request(t, restarted, http.MethodPost, "/v1/agents/"+agentRecord.ID+"/heartbeat", nil); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing heartbeat token returned %d", response.Code)
	}
	if response := requestWithToken(t, restarted, http.MethodPost, "/v1/agents/"+agentRecord.ID+"/heartbeat", nil, agentRecord.HeartbeatToken); response.Code != http.StatusOK {
		t.Fatalf("heartbeat returned %d", response.Code)
	}
	if response := request(t, restarted, http.MethodGet, "/readyz", nil); response.Code != http.StatusOK {
		t.Fatalf("readiness returned %d: %s", response.Code, response.Body.String())
	}
	events, err := readPostgresAudit(context.Background(), db)
	if err != nil || len(events) != 2 || !verifyAuditChain(events) {
		t.Fatalf("invalid persistent audit: count=%d, err=%v", len(events), err)
	}
}
