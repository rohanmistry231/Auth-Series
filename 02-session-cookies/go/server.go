package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	sessionSecret = getEnv("SESSION_SECRET", "dev-secret-change-in-production-32chars")
	sessionTTL    = 1 * time.Hour
	idleTTL       = 15 * time.Minute
)

var users = map[string]string{
	"alice": getEnv("ALICE_PASSWORD", "password-alice"),
	"bob":   getEnv("BOB_PASSWORD", "password-bob"),
}

type Session struct {
	UserID          string
	Role            string
	ExpiresAbsolute time.Time
	ExpiresIdle     time.Time
	CSRFToken       string
}

var (
	store   = make(map[string]*Session)
	storeMu sync.RWMutex
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sign(value string) string {
	mac := hmac.New(sha256.New, []byte(sessionSecret))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

func createSignedSessionID() string {
	sessionID := randomHex(16)
	return sessionID + "." + sign(sessionID)
}

func verifySignedSessionID(signed string) (string, bool) {
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	sessionID, signature := parts[0], parts[1]
	expected := sign(sessionID)
	return sessionID, hmac.Equal([]byte(signature), []byte(expected))
}

func getSession(r *http.Request) *Session {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil
	}

	sid, ok := verifySignedSessionID(cookie.Value)
	if !ok {
		return nil
	}

	storeMu.RLock()
	session, exists := store[sid]
	storeMu.RUnlock()

	if !exists {
		return nil
	}

	now := time.Now()
	if now.After(session.ExpiresAbsolute) {
		storeMu.Lock()
		delete(store, sid)
		storeMu.Unlock()
		return nil
	}
	if now.After(session.ExpiresIdle) {
		storeMu.Lock()
		delete(store, sid)
		storeMu.Unlock()
		return nil
	}

	session.ExpiresIdle = now.Add(idleTTL)
	return session
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func setSessionCookie(w http.ResponseWriter, signed string, maxAge int) {
	cookie := http.Cookie{
		Name:     "session_id",
		Value:    signed,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
		Path:     "/",
	}
	http.SetCookie(w, &cookie)
}

func deleteSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Path:     "/",
	})
}

func publicHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "This is public — no session required",
	})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	expected, exists := users[data.Username]
	if !exists || expected != data.Password {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	signed := createSignedSessionID()
	sid := strings.SplitN(signed, ".", 2)[0]
	now := time.Now()

	storeMu.Lock()
	store[sid] = &Session{
		UserID:          data.Username,
		Role:            map[bool]string{true: "admin", false: "user"}[data.Username == "alice"],
		ExpiresAbsolute: now.Add(sessionTTL),
		ExpiresIdle:     now.Add(idleTTL),
	}
	storeMu.Unlock()

	setSessionCookie(w, signed, int(sessionTTL.Seconds()))
	writeJSON(w, http.StatusOK, map[string]string{
		"message": fmt.Sprintf("Logged in as %s", data.Username),
	})
}

func meHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not authenticated"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"user_id": session.UserID,
		"role":    session.Role,
	})
}

func csrfTokenHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not authenticated"})
		return
	}
	token := randomHex(32)
	session.CSRFToken = token
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	if session == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Not authenticated"})
		return
	}

	var data struct {
		CSRFToken string `json:"csrf_token"`
		Payload   any    `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	if session.CSRFToken == "" || session.CSRFToken != data.CSRFToken {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "Invalid CSRF token"})
		return
	}

	session.CSRFToken = ""
	writeJSON(w, http.StatusOK, map[string]any{
		"message": "Data created",
		"data":    data.Payload,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session_id")
	if err == nil {
		sid := strings.SplitN(cookie.Value, ".", 2)[0]
		storeMu.Lock()
		delete(store, sid)
		storeMu.Unlock()
	}
	deleteSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"message": "Logged out"})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/public", publicHandler)
	mux.HandleFunc("/csrf-token", csrfTokenHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/me", meHandler)
	mux.HandleFunc("/data", dataHandler)
	mux.HandleFunc("/logout", logoutHandler)

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Server running at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
