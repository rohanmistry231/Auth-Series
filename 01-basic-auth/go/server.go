package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

var users = map[string]string{
	"alice": getEnv("ALICE_PASSWORD", "password-alice"),
	"bob":   getEnv("BOB_PASSWORD", "password-bob"),
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func decodeBasicAuth(header string) (username, password string, ok bool) {
	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}

	decoded, err := base64.StdEncoding.DecodeString(header[6:])
	if err != nil {
		return "", "", false
	}

	pair := string(decoded)
	colon := strings.IndexByte(pair, ':')
	if colon == -1 {
		return "", "", false
	}

	return pair[:colon], pair[colon+1:], true
}

func authenticate(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	user, pass, ok := decodeBasicAuth(auth)
	if !ok {
		return "", false
	}

	expected, exists := users[user]
	if !exists || expected != pass {
		return "", false
	}

	return user, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func publicHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "This is public — no auth required",
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	user, ok := authenticate(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Basic")
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "Invalid or missing credentials",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"username": user,
		"message":  "Authenticated via Basic Auth",
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/public", publicHandler)
	mux.HandleFunc("/protected", protectedHandler)

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Server running at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
