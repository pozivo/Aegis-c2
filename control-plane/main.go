package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

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

func id() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil { panic(err) }
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func main() {
	s := &store{engagements: map[string]engagement{}, agents: map[string]agent{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/engagements", func(w http.ResponseWriter, r *http.Request) {
		var e engagement
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&e); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"}); return
		}
		if e.Name == "" || len(e.AllowedCIDRs) == 0 || !e.ExpiresAt.After(time.Now()) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "name, future expiry, and scope are required"}); return
		}
		e.ID, e.CreatedAt = id(), time.Now().UTC()
		s.Lock(); s.engagements[e.ID] = e; s.audit = append(s.audit, auditEvent{ID:id(), Time:time.Now().UTC(), Action:"engagement.created", SubjectID:e.ID}); s.Unlock()
		writeJSON(w, http.StatusCreated, e)
	})
	mux.HandleFunc("POST /v1/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
		var a agent
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&a); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"}); return
		}
		s.Lock(); defer s.Unlock()
		e, ok := s.engagements[a.EngagementID]
		if !ok || !e.ExpiresAt.After(time.Now()) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "engagement unavailable"}); return
		}
		a.ID, a.LastSeen = id(), time.Now().UTC(); s.agents[a.ID] = a
		s.audit = append(s.audit, auditEvent{ID:id(), Time:time.Now().UTC(), Action:"agent.enrolled", SubjectID:a.ID, Details:map[string]any{"engagement_id":a.EngagementID}})
		writeJSON(w, http.StatusCreated, a)
	})
	mux.HandleFunc("POST /v1/agents/{agentID}/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("agentID")
		s.Lock(); defer s.Unlock()
		a, ok := s.agents[agentID]; if !ok { writeJSON(w, http.StatusNotFound, map[string]string{"error":"agent not found"}); return }
		a.LastSeen = time.Now().UTC(); s.agents[agentID] = a
		writeJSON(w, http.StatusOK, map[string]any{"accepted":true, "server_time":time.Now().UTC()})
	})
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, _ *http.Request) {
		s.RLock(); defer s.RUnlock(); writeJSON(w, http.StatusOK, s.audit)
	})

	server := &http.Server{Addr:":8080", Handler:mux, ReadHeaderTimeout:5*time.Second, ReadTimeout:10*time.Second, WriteTimeout:10*time.Second, IdleTimeout:60*time.Second}
	log.Printf("Aegis control plane listening on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
