package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, 10, 2, 20, 0, 0, 0, time.UTC)

func request(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func createEngagement(t *testing.T, handler http.Handler) engagement {
	t.Helper()
	response := request(t, handler, http.MethodPost, "/v1/engagements", map[string]any{
		"name":          "local-lab",
		"allowed_cidrs": []string{"10.20.0.0/16"},
		"expires_at":    fixedNow.Add(time.Hour),
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	var result engagement
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestHealthAndReadiness(t *testing.T) {
	handler := newHandler(newStore(), func() time.Time { return fixedNow })
	for _, path := range []string{"/healthz", "/readyz"} {
		response := request(t, handler, http.MethodGet, path, nil)
		if response.Code != http.StatusOK {
			t.Fatalf("%s returned %d", path, response.Code)
		}
	}
}

func TestEngagementRejectsInvalidCIDR(t *testing.T) {
	handler := newHandler(newStore(), func() time.Time { return fixedNow })
	response := request(t, handler, http.MethodPost, "/v1/engagements", map[string]any{
		"name":          "broken-scope",
		"allowed_cidrs": []string{"not-a-network"},
		"expires_at":    fixedNow.Add(time.Hour),
	})
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", response.Code)
	}
}

func TestEnrollmentAndHeartbeat(t *testing.T) {
	store := newStore()
	handler := newHandler(store, func() time.Time { return fixedNow })
	e := createEngagement(t, handler)
	response := request(t, handler, http.MethodPost, "/v1/agents/enroll", map[string]any{
		"engagement_id": e.ID,
		"hostname":      "lab-host",
		"os":            "linux",
		"architecture":  "amd64",
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	var enrolled agent
	if err := json.NewDecoder(response.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	heartbeat := request(t, handler, http.MethodPost, "/v1/agents/"+enrolled.ID+"/heartbeat", nil)
	if heartbeat.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", heartbeat.Code)
	}
	if len(store.audit) != 2 {
		t.Fatalf("expected two audit events, got %d", len(store.audit))
	}
}

func TestExpiredEngagementBlocksHeartbeat(t *testing.T) {
	clock := fixedNow
	store := newStore()
	handler := newHandler(store, func() time.Time { return clock })
	e := createEngagement(t, handler)
	response := request(t, handler, http.MethodPost, "/v1/agents/enroll", map[string]any{
		"engagement_id": e.ID,
		"hostname":      "lab-host",
		"os":            "linux",
		"architecture":  "amd64",
	})
	var enrolled agent
	if err := json.NewDecoder(response.Body).Decode(&enrolled); err != nil {
		t.Fatal(err)
	}
	clock = fixedNow.Add(2 * time.Hour)
	heartbeat := request(t, handler, http.MethodPost, "/v1/agents/"+enrolled.ID+"/heartbeat", nil)
	if heartbeat.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", heartbeat.Code)
	}
}

func TestUnknownFieldsAreRejected(t *testing.T) {
	handler := newHandler(newStore(), func() time.Time { return fixedNow })
	response := request(t, handler, http.MethodPost, "/v1/engagements", map[string]any{
		"name":          "local-lab",
		"allowed_cidrs": []string{"10.20.0.0/16"},
		"expires_at":    fixedNow.Add(time.Hour),
		"unexpected":    true,
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", response.Code)
	}
}
