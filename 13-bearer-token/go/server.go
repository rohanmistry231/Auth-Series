package main

import (
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

var tokenTTL = getIntEnv("TOKEN_TTL", 3600)

type user struct {
	Password string
	Scopes   []string
}

type tokenRecord struct {
	Sub     string
	Scopes  []string
	Iat     int64
	Exp     int64
	Revoked bool
}

var users = map[string]user{
	"alice": {getEnv("ALICE_PASSWORD", "password-alice"), []string{"read", "write"}},
	"bob":   {getEnv("BOB_PASSWORD", "password-bob"), []string{"read"}},
}

var tokens = make(map[string]*tokenRecord)

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

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func generateToken() string {
	b := make([]byte, 48)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, s string, status int) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(s))
}

func parseForm(r *http.Request) {
	r.ParseForm()
}

func getBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

func validateToken(tokenStr string) *tokenRecord {
	th := sha256Hash(tokenStr)
	rec := tokens[th]
	if rec == nil || rec.Revoked || time.Now().Unix() > rec.Exp {
		return nil
	}
	return rec
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			sendHTML(w, "Not found", 404)
			return
		}
		sendHTML(w, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Bearer Token Auth</h2>
<form method="post" action="/login"><p><label>User: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p><p><button type="submit">Get Token</button></p></form>
<form method="get" action="/protected"><p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">GET /protected</button></p></form>
<form method="post" action="/introspect"><p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">Introspect</button></p></form>
<form method="post" action="/revoke"><p><label>Token: <input name="token" size="50"></label></p>
<p><button type="submit">Revoke</button></p></form>
</body></html>`, 200)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		username := r.FormValue("username")
		password := r.FormValue("password")
		user, ok := users[username]
		if !ok || user.Password != password {
			sendJSON(w, 401, map[string]string{"error": "Invalid credentials"})
			return
		}

		token := generateToken()
		th := sha256Hash(token)
		now := time.Now().Unix()
		tokens[th] = &tokenRecord{
			Sub:     username,
			Scopes:  user.Scopes,
			Iat:     now,
			Exp:     now + int64(tokenTTL),
			Revoked: false,
		}

		sendJSON(w, 200, map[string]any{
			"access_token": token,
			"token_type":   "Bearer",
			"expires_in":   tokenTTL,
			"scope":        strings.Join(user.Scopes, " "),
		})
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		tokenStr := r.URL.Query().Get("token")
		if tokenStr == "" {
			tokenStr = getBearer(r)
		}
		if tokenStr == "" {
			sendJSON(w, 401, map[string]string{"error": "Missing token"})
			return
		}
		rec := validateToken(tokenStr)
		if rec == nil {
			sendJSON(w, 401, map[string]string{"error": "Invalid or expired token"})
			return
		}
		sendJSON(w, 200, map[string]any{
			"message": fmt.Sprintf("Authenticated as %s", rec.Sub),
			"scopes":  rec.Scopes,
			"exp":     rec.Exp,
		})
	})

	mux.HandleFunc("/introspect", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		tokenStr := r.FormValue("token")
		th := sha256Hash(tokenStr)
		rec := tokens[th]
		if rec == nil || rec.Revoked || time.Now().Unix() > rec.Exp {
			sendJSON(w, 200, map[string]any{"active": false})
			return
		}
		sendJSON(w, 200, map[string]any{
			"active":     true,
			"sub":        rec.Sub,
			"scope":      strings.Join(rec.Scopes, " "),
			"token_type": "Bearer",
			"exp":        rec.Exp,
			"iat":        rec.Iat,
		})
	})

	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		tokenStr := r.FormValue("token")
		th := sha256Hash(tokenStr)
		if rec := tokens[th]; rec != nil {
			rec.Revoked = true
		}
		sendJSON(w, 200, map[string]string{"result": "ok"})
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Bearer Token Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
