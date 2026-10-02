package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const maxBodySize = 32 << 10

type engagement struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	AllowedCIDRs []string  `json:"allowed_cidrs"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type agent struct {
	ID           string            `json:"id"`
	EngagementID string            `json:"engagement_id"`
	Hostname     string            `json:"hostname"`
	OS           string            `json:"os"`
	Architecture string            `json:"architecture"`
	Labels       map[string]string `json:"labels,omitempty"`
	LastSeen     time.Time         `json:"last_seen"`
}

type auditEvent struct {
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Action    string         `json:"action"`
	SubjectID string         `json:"subject_id"`
	Details   map[string]any `json:"details,omitempty"`
}

type store struct {
	sync.RWMutex
	engagements map[string]engagement
	agents      map[string]agent
	audit       []auditEvent
}

func newStore() *store {
	return &store{engagements: map[string]engagement{}, agents: map[string]agent{}}
}

func id() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) == nil {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func validateEngagement(e engagement, now time.Time) error {
	if strings.TrimSpace(e.Name) == "" {
		return errors.New("name is required")
	}
	if len(e.AllowedCIDRs) == 0 {
		return errors.New("at least one allowed CIDR is required")
	}
	if !e.ExpiresAt.After(now) {
		return errors.New("expiry must be in the future")
	}
	for _, raw := range e.AllowedCIDRs {
		if _, err := netip.ParsePrefix(raw); err != nil {
			return errors.New("scope contains an invalid CIDR")
		}
	}
	return nil
}

func validateAgent(a agent) error {
	if strings.TrimSpace(a.EngagementID) == "" || strings.TrimSpace(a.Hostname) == "" {
		return errors.New("engagement_id and hostname are required")
	}
	if len(a.Hostname) > 253 || len(a.OS) > 64 || len(a.Architecture) > 64 || len(a.Labels) > 32 {
		return errors.New("inventory fields exceed limits")
	}
	for key, value := range a.Labels {
		if len(key) > 64 || len(value) > 256 {
			return errors.New("label exceeds limits")
		}
	}
	return nil
}

func newHandler(s *store, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /v1/engagements", func(w http.ResponseWriter, r *http.Request) {
		var e engagement
		if err := decodeJSON(w, r, &e); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		current := now().UTC()
		if err := validateEngagement(e, current); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		e.ID, e.CreatedAt = id(), current
		s.Lock()
		s.engagements[e.ID] = e
		s.audit = append(s.audit, auditEvent{ID: id(), Time: current, Action: "engagement.created", SubjectID: e.ID})
		s.Unlock()
		writeJSON(w, http.StatusCreated, e)
	})
	mux.HandleFunc("POST /v1/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		var a agent
		if err := decodeJSON(w, r, &a); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
			return
		}
		if err := validateAgent(a); err != nil {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
			return
		}
		current := now().UTC()
		s.Lock()
		defer s.Unlock()
		e, ok := s.engagements[a.EngagementID]
		if !ok || !e.ExpiresAt.After(current) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "engagement unavailable"})
			return
		}
		a.ID, a.LastSeen = id(), current
		s.agents[a.ID] = a
		s.audit = append(s.audit, auditEvent{ID: id(), Time: current, Action: "agent.enrolled", SubjectID: a.ID, Details: map[string]any{"engagement_id": a.EngagementID}})
		writeJSON(w, http.StatusCreated, a)
	})
	mux.HandleFunc("POST /v1/agents/{agentID}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("agentID")
		current := now().UTC()
		s.Lock()
		defer s.Unlock()
		a, ok := s.agents[agentID]
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		e, ok := s.engagements[a.EngagementID]
		if !ok || !e.ExpiresAt.After(current) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "engagement expired"})
			return
		}
		a.LastSeen = current
		s.agents[agentID] = a
		writeJSON(w, http.StatusOK, map[string]any{"accepted": true, "server_time": current})
	})
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, _ *http.Request) {
		s.RLock()
		defer s.RUnlock()
		writeJSON(w, http.StatusOK, s.audit)
	})
	return mux
}

func main() {
	handler := newHandler(newStore(), time.Now)
	server := &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Aegis control plane listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
