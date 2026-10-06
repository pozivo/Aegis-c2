package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperatorAuth(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef"
	if _, err := operatorAuth(http.NotFoundHandler(), "short"); err == nil {
		t.Fatal("accepted short operator token")
	}
	handler, err := operatorAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path, token string
		want                int
	}{
		{http.MethodPost, "/v1/engagements", "", http.StatusUnauthorized},
		{http.MethodPost, "/v1/engagements", "wrong", http.StatusUnauthorized},
		{http.MethodPost, "/v1/engagements", secret, http.StatusNoContent},
		{http.MethodGet, "/v1/audit", "", http.StatusUnauthorized},
		{http.MethodGet, "/v1/audit", secret, http.StatusNoContent},
		{http.MethodGet, "/healthz", "", http.StatusNoContent},
		{http.MethodPost, "/v1/agents/enroll", "", http.StatusNoContent},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(""))
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != tc.want {
			t.Errorf("%s %s token=%t: got %d, want %d", tc.method, tc.path, tc.token != "", w.Code, tc.want)
		}
	}
}
