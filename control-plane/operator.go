package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
)

func operatorAuth(next http.Handler, secret string) (http.Handler, error) {
	if len(secret) < 32 {
		return nil, errors.New("AEGIS_OPERATOR_TOKEN must be at least 32 characters")
	}
	expected := sha256.Sum256([]byte(secret))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodPost && r.URL.Path == "/v1/engagements") ||
			(r.Method == http.MethodGet && r.URL.Path == "/v1/audit") {
			token, ok := bearerToken(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "operator token required"})
				return
			}
			actual := sha256.Sum256([]byte(token))
			if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid operator token"})
				return
			}
		}
		next.ServeHTTP(w, r)
	}), nil
}
