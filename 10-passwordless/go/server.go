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
	"strconv"
	"strings"
	"time"
)

var (
	secretKey   = getEnv("MAGIC_LINK_SECRET", "change-me-in-production")
	tokenTTL    = getIntEnv("TOKEN_TTL_SECONDS", 900)
	tokenHashes = make(map[string]map[string]any)
	usedTokens  = make(map[string]bool)
)

var users = map[string]string{
	"alice@example.com": newUUID(),
	"bob@example.com":   newUUID(),
}

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func getIntEnv(k string, f int) int {
	if v := os.Getenv(k); v != "" {
		i, err := strconv.Atoi(v)
		if err == nil {
			return i
		}
	}
	return f
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hmacSign(payload string) string {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, s string, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write([]byte(s))
}

func parseForm(r *http.Request) {
	r.ParseForm()
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			sendHTML(w, "Not found", 404)
			return
		}
		sendHTML(w, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Passwordless (Magic Link) Demo</h2>
<form method="post" action="/auth/request">
<p><label>Email: <input name="email" value="alice@example.com"></label></p>
<p><button type="submit">Send Magic Link</button></p>
</form></body></html>`, 200)
	})

	mux.HandleFunc("/auth/request", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		email := r.FormValue("email")
		if _, ok := users[email]; !ok {
			sendJSON(w, 404, map[string]string{"error": "Unknown email"})
			return
		}

		tokenID := newUUID()
		exp := time.Now().Unix() + int64(tokenTTL)
		payload := fmt.Sprintf("%s:%s:%d", email, tokenID, exp)
		sig := hmacSign(payload)
		token := fmt.Sprintf("%s.%s", payload, sig)
		th := sha256Hash(token)

		tokenHashes[th] = map[string]any{
			"email": email,
			"exp":   exp,
		}

		magicURL := fmt.Sprintf("http://127.0.0.1:8000/auth/verify?token=%s", token)
		log.Printf("Magic link for %s:", email)
		log.Printf("  %s", magicURL)

		sendJSON(w, 200, map[string]any{
			"message":    fmt.Sprintf("Magic link sent to %s", email),
			"magic_url":  magicURL,
			"expires_in": tokenTTL,
		})
	})

	mux.HandleFunc("/auth/verify", func(w http.ResponseWriter, r *http.Request) {
		rawToken := r.URL.Query().Get("token")
		if rawToken == "" {
			sendHTML(w, "Missing token", 400)
			return
		}

		lastDot := strings.LastIndex(rawToken, ".")
		if lastDot < 0 {
			sendHTML(w, "Invalid token format", 400)
			return
		}

		payload := rawToken[:lastDot]
		sig := rawToken[lastDot+1:]

		expectedSig := hmacSign(payload)
		if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
			sendHTML(w, "Invalid signature", 401)
			return
		}

		parts := strings.SplitN(payload, ":", 3)
		if len(parts) != 3 {
			sendHTML(w, "Malformed payload", 400)
			return
		}
		email, expStr := parts[0], parts[2]
		exp, _ := strconv.ParseInt(expStr, 10, 64)

		if time.Now().Unix() > exp {
			sendHTML(w, "Token expired", 401)
			return
		}

		th := sha256Hash(rawToken)
		if usedTokens[th] {
			sendHTML(w, "Token already used", 401)
			return
		}
		usedTokens[th] = true

		sessionToken := newUUID()
		sendHTML(w, fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Authenticated ✓</h2>
<p>Welcome, <strong>%s</strong>!</p>
<p>Session: <code>%s...</code></p>
</body></html>`, email, sessionToken[:16]), 200)
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Magic Link Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
