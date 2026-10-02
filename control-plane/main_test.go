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

func requestWithToken(t *testing.T, handler http.Handler, method, path string, body any, token string) *httptest.ResponseRecorder {
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}

func request(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return requestWithToken(t, handler, method, path, body, "")
}

func createEngagement(t *testing.T, handler http.Handler) engagementCreated {
	t.Helper()
	response := request(t, handler, http.MethodPost, "/v1/engagements", map[string]any{
		"name":          "local-lab",
		"allowed_cidrs": []string{"10.20.0.0/16"},
		"expires_at":    fixedNow.Add(time.Hour),
	})
	if response.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", response.Code, response.Body.String())
	}
	var result engagementCreated
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
	response := requestWithToken(t, handler, http.MethodPost, "/v1/agents/enroll", map[string]any{
		"engagement_id": e.ID,
		"hostname":      "lab-host",
		"os":            "linux",
		"architecture":  "amd64",
	}, e.EnrollmentToken)
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
	response := requestWithToken(t, handler, http.MethodPost, "/v1/agents/enroll", map[string]any{
		"engagement_id": e.ID,
		"hostname":      "lab-host",
		"os":            "linux",
		"architecture":  "amd64",
	}, e.EnrollmentToken)
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

func TestEnrollmentTokenIsRequiredAndSingleUse(t *testing.T) {
	store := newStore()
	handler := newHandler(store, func() time.Time { return fixedNow })
	e := createEngagement(t, handler)
	body := map[string]any{
		"engagement_id": e.ID,
		"hostname":      "lab-host",
		"os":            "linux",
		"architecture":  "amd64",
	}
	missing := request(t, handler, http.MethodPost, "/v1/agents/enroll", body)
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing token to return 401, got %d", missing.Code)
	}
	invalid := requestWithToken(t, handler, http.MethodPost, "/v1/agents/enroll", body, "wrong-token")
	if invalid.Code != http.StatusUnauthorized {
		t.Fatalf("expected invalid token to return 401, got %d", invalid.Code)
	}
	accepted := requestWithToken(t, handler, http.MethodPost, "/v1/agents/enroll", body, e.EnrollmentToken)
	if accepted.Code != http.StatusCreated {
		t.Fatalf("expected valid token to return 201, got %d", accepted.Code)
	}
	reused := requestWithToken(t, handler, http.MethodPost, "/v1/agents/enroll", body, e.EnrollmentToken)
	if reused.Code != http.StatusUnauthorized {
		t.Fatalf("expected reused token to return 401, got %d", reused.Code)
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
