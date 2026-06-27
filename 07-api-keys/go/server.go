package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	rateWindow = 60
	rateMax    = 10
)

type apiKeyEntry struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Prefix           string   `json:"prefix"`
	KeyHash          string   `json:"-"`
	KeySuffix        string   `json:"key_suffix"`
	Scopes           []string `json:"scopes"`
	CreatedAt        int64    `json:"created_at"`
	ExpiresAt        int64    `json:"expires_at"`
	LastUsed         int64    `json:"last_used"`
	RateWindowStart  int64    `json:"-"`
	RateWindowCount  int      `json:"-"`
}

var (
	store   = make(map[string]*apiKeyEntry)
	storeMu sync.RWMutex
)

func hashKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return fmt.Sprintf("%x", h)
}

func generateKey(prefix string) string {
	raw := make([]byte, 32)
	rand.Read(raw)
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(raw)
}

func createKey(name string, scopes []string, expiresInDays int) (*apiKeyEntry, string) {
	key := generateKey("user_stripe_key")
	keyHash := hashKey(key)

	parts := strings.SplitN(key, "_", 3)
	prefix := parts[0] + "_" + parts[1]

	entry := &apiKeyEntry{
		ID:        fmt.Sprintf("%x", sha256.Sum256([]byte(key)))[:16],
		Name:      name,
		Prefix:    prefix,
		KeyHash:   keyHash,
		KeySuffix: key[len(key)-4:],
		Scopes:    scopes,
		CreatedAt: time.Now().Unix(),
		ExpiresAt: 0,
	}
	if expiresInDays > 0 {
		entry.ExpiresAt = time.Now().Add(time.Duration(expiresInDays) * 24 * time.Hour).Unix()
	}

	storeMu.Lock()
	store[keyHash] = entry
	storeMu.Unlock()

	return entry, key
}

func authenticate(r *http.Request) *apiKeyEntry {
	apiKey := r.Header.Get("X-API-Key")
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		apiKey = strings.TrimPrefix(auth, "Bearer ")
	}
	if apiKey == "" {
		return nil
	}

	keyHash := hashKey(apiKey)

	storeMu.RLock()
	entry, exists := store[keyHash]
	storeMu.RUnlock()

	if !exists {
		return nil
	}

	if entry.ExpiresAt > 0 && time.Now().Unix() > entry.ExpiresAt {
		return nil
	}

	now := time.Now().Unix()
	if now-entry.RateWindowStart > rateWindow {
		entry.RateWindowStart = now
		entry.RateWindowCount = 0
	}
	entry.RateWindowCount++
	if entry.RateWindowCount > rateMax {
		return nil
	}

	entry.LastUsed = now
	return entry
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func keysHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		storeMu.RLock()
		result := make([]map[string]any, 0)
		for _, entry := range store {
			result = append(result, map[string]any{
				"id": entry.ID, "name": entry.Name, "prefix": entry.Prefix,
				"key_suffix": entry.KeySuffix, "scopes": entry.Scopes,
			})
		}
		storeMu.RUnlock()
		writeJSON(w, http.StatusOK, result)

	case http.MethodPost:
		var data struct {
			Name          string   `json:"name"`
			Scopes        []string `json:"scopes"`
			ExpiresInDays int      `json:"expires_in_days"`
		}
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			data.Name = "Untitled"
			data.Scopes = []string{"read"}
		}
		entry, key := createKey(data.Name, data.Scopes, data.ExpiresInDays)
		writeJSON(w, http.StatusOK, map[string]any{
			"id": entry.ID, "name": entry.Name, "prefix": entry.Prefix,
			"key_suffix": entry.KeySuffix, "key": key, "scopes": entry.Scopes,
		})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

var rotateRE = regexp.MustCompile(`^/keys/([^/]+)/rotate$`)
var revokeRE = regexp.MustCompile(`^/keys/([^/]+)/revoke$`)

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/keys", keysHandler)

	mux.HandleFunc("/keys/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		if matches := rotateRE.FindStringSubmatch(path); matches != nil && r.Method == http.MethodPost {
			keyID := matches[1]
			storeMu.Lock()
			var found *apiKeyEntry
			for kh, entry := range store {
				if entry.ID == keyID {
					found = entry
					delete(store, kh)
					break
				}
			}
			storeMu.Unlock()
			if found == nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
				return
			}
			newEntry, newKey := createKey(found.Name, found.Scopes, 30)
			writeJSON(w, http.StatusOK, map[string]any{
				"message": "Key rotated", "old_id": keyID,
				"new_id": newEntry.ID, "new_key": newKey,
			})
			return
		}

		if matches := revokeRE.FindStringSubmatch(path); matches != nil && r.Method == http.MethodPost {
			keyID := matches[1]
			storeMu.Lock()
			for kh, entry := range store {
				if entry.ID == keyID {
					delete(store, kh)
					storeMu.Unlock()
					writeJSON(w, http.StatusOK, map[string]string{"message": "Key revoked"})
					return
				}
			}
			storeMu.Unlock()
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
			return
		}
	})

	mux.HandleFunc("/api/public", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"message": "Public endpoint"})
	})

	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		entry := authenticate(r)
		if entry == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing, invalid, or expired API key"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"message": "Protected data", "key_name": entry.Name, "scopes": entry.Scopes})
	})

	mux.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
		entry := authenticate(r)
		if entry == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing or invalid API key"})
			return
		}
		hasAdmin := false
		for _, s := range entry.Scopes {
			if s == "admin" {
				hasAdmin = true
				break
			}
		}
		if !hasAdmin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Admin scope required"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"message": "Admin data", "key_name": entry.Name})
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("API Key Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

var _ = hmac.Equal
