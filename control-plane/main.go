package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

const maxBodySize = 32 << 10

type engagement struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	AllowedCIDRs []string  `json:"allowed_cidrs"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
}

type engagementCreated struct {
	engagement
	EnrollmentToken string `json:"enrollment_token"`
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

type agentEnrolled struct {
	agent
	HeartbeatToken string `json:"heartbeat_token"`
}

type auditEvent struct {
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Action    string         `json:"action"`
	SubjectID string         `json:"subject_id"`
	Details   map[string]any `json:"details,omitempty"`
	PrevHash  string         `json:"prev_hash,omitempty"`
	Hash      string         `json:"hash"`
}

type auditPayload struct {
	ID        string         `json:"id"`
	Time      time.Time      `json:"time"`
	Action    string         `json:"action"`
	SubjectID string         `json:"subject_id"`
	Details   map[string]any `json:"details,omitempty"`
	PrevHash  string         `json:"prev_hash,omitempty"`
}

type store struct {
	sync.RWMutex
	engagements     map[string]engagement
	enrollmentToken map[string][sha256.Size]byte
	agents          map[string]agent
	heartbeatTokens map[string][sha256.Size]byte
	audit           []auditEvent
}

func newStore() *store {
	return &store{
		engagements:     map[string]engagement{},
		enrollmentToken: map[string][sha256.Size]byte{},
		agents:          map[string]agent{},
		heartbeatTokens: map[string][sha256.Size]byte{},
	}
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

func bearerToken(r *http.Request) (string, bool) {
	value := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(value, prefix) {
		return "", false
	}
	token := strings.TrimSpace(strings.TrimPrefix(value, prefix))
	return token, token != ""
}

func tokenMatches(token string, expected [sha256.Size]byte) bool {
	actual := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(actual[:], expected[:]) == 1
}

func auditHash(event auditEvent) string {
	payload, err := json.Marshal(auditPayload{
		ID:        event.ID,
		Time:      event.Time,
		Action:    event.Action,
		SubjectID: event.SubjectID,
		Details:   event.Details,
		PrevHash:  event.PrevHash,
	})
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func appendAudit(s *store, event auditEvent) {
	if len(s.audit) > 0 {
		event.PrevHash = s.audit[len(s.audit)-1].Hash
	}
	event.Hash = auditHash(event)
	s.audit = append(s.audit, event)
}

func verifyAuditChain(events []auditEvent) bool {
	previous := ""
	for _, event := range events {
		if event.PrevHash != previous || event.Hash != auditHash(event) {
			return false
		}
		previous = event.Hash
	}
	return true
}

func newHandler(s *store, now func() time.Time) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		s.RLock()
		validAudit := verifyAuditChain(s.audit)
		s.RUnlock()
		if !validAudit {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "audit integrity failure"})
			return
		}
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
		enrollmentToken := id()
		tokenHash := sha256.Sum256([]byte(enrollmentToken))
		s.Lock()
		s.engagements[e.ID] = e
		s.enrollmentToken[e.ID] = tokenHash
		appendAudit(s, auditEvent{ID: id(), Time: current, Action: "engagement.created", SubjectID: e.ID})
		s.Unlock()
		writeJSON(w, http.StatusCreated, engagementCreated{engagement: e, EnrollmentToken: enrollmentToken})
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
		token, ok := bearerToken(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "enrollment token required"})
			return
		}
		s.Lock()
		defer s.Unlock()
		e, ok := s.engagements[a.EngagementID]
		if !ok || !e.ExpiresAt.After(current) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "engagement unavailable"})
			return
		}
		expectedToken, ok := s.enrollmentToken[a.EngagementID]
		if !ok || !tokenMatches(token, expectedToken) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid enrollment token"})
			return
		}
		a.ID, a.LastSeen = id(), current
		heartbeatToken := id()
		s.agents[a.ID] = a
		s.heartbeatTokens[a.ID] = sha256.Sum256([]byte(heartbeatToken))
		delete(s.enrollmentToken, a.EngagementID)
		appendAudit(s, auditEvent{ID: id(), Time: current, Action: "agent.enrolled", SubjectID: a.ID, Details: map[string]any{"engagement_id": a.EngagementID}})
		writeJSON(w, http.StatusCreated, agentEnrolled{agent: a, HeartbeatToken: heartbeatToken})
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
		token, present := bearerToken(r)
		if !present || !tokenMatches(token, s.heartbeatTokens[agentID]) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid heartbeat token"})
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
	url := os.Getenv("AEGIS_DATABASE_URL")
	if url == "" {
		log.Fatal("AEGIS_DATABASE_URL is required")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		log.Fatal(err)
	}
	handler, err := operatorAuth(newPostgresHandler(db, time.Now), os.Getenv("AEGIS_OPERATOR_TOKEN"))
	if err != nil {
		log.Fatal(err)
	}
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
