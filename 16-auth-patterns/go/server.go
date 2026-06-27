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
	"strings"
	"time"
)

var users = map[string]string{
	"alice": getEnv("ALICE_PASSWORD", "password-alice"),
}

var (
	bffSessions   = make(map[string]map[string]any)
	refreshTokens = make(map[string]map[string]any)
	gatewayTokens = make(map[string]map[string]any)
)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" { return v }
	return f
}

func sha256hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sendJSON(w http.ResponseWriter, status int, v any, extraHeaders ...map[string]string) {
	for _, h := range extraHeaders {
		for k, v := range h { w.Header().Set(k, v) }
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, body string, status int) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func pageHTML(title, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html><html><body style="font-family:sans-serif;max-width:700px;margin:40px auto">%s</body></html>`, body)
}

func parseForm(r *http.Request) { r.ParseForm() }

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" { sendHTML(w, "Not found", 404); return }
		sendHTML(w, pageHTML("Auth Patterns", `
<h2>Auth Patterns Demo</h2>
<ul><li><a href="/bff/login">BFF Pattern</a></li>
<li><a href="/token-rotation">Token Rotation</a></li>
<li><a href="/gateway">Gateway Auth</a></li></ul>`), 200)
	})

	// BFF
	mux.HandleFunc("/bff/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			sendHTML(w, pageHTML("BFF Login", `
<h2>BFF Login</h2>
<form method="post" action="/bff/login"><p><label>User: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p><p><button type="submit">Login</button></p></form>`), 200)
			return
		}
		parseForm(r)
		u, p := r.FormValue("username"), r.FormValue("password")
		if users[u] != p { sendJSON(w, 401, map[string]string{"error": "Invalid"}); return }
		sid := newUUID()
		bffSessions[sid] = map[string]any{"username": u, "access_token": newUUID()}
		http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, HttpOnly: true, SameSite: http.SameSiteLaxMode, Path: "/"})
		sendJSON(w, 200, map[string]any{"message": fmt.Sprintf("Logged in as %s", u)})
	})

	mux.HandleFunc("/bff/api/data", func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("session_id")
		session := bffSessions[cookie.Value]
		if session == nil { sendJSON(w, 401, map[string]string{"error": "Not authenticated"}); return }
		sendJSON(w, 200, map[string]any{"message": fmt.Sprintf("Protected data for %s", session["username"]), "data": "secret-42"})
	})

	// Token Rotation
	mux.HandleFunc("/token/issue", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		if users[r.FormValue("username")] != r.FormValue("password") { sendJSON(w, 401, map[string]string{"error": "Invalid"}); return }
		rt := newUUID() + newUUID()
		family := newUUID()
		refreshTokens[sha256hash(rt)] = map[string]any{"username": r.FormValue("username"), "family": family, "exp": time.Now().Unix() + 604800, "revoked": false}
		sendJSON(w, 200, map[string]any{"access_token": newUUID(), "refresh_token": rt, "expires_in": 900})
	})

	mux.HandleFunc("/token/refresh", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		rth := sha256hash(r.FormValue("refresh_token"))
		rec := refreshTokens[rth]
		if rec == nil { sendJSON(w, 401, map[string]string{"error": "Invalid token"}); return }
		if rec["revoked"].(bool) {
			family := rec["family"].(string)
			for h, rec2 := range refreshTokens {
				if rec2["family"].(string) == family { rec2["revoked"] = true }
				_ = h
			}
			sendJSON(w, 401, map[string]string{"error": "Token reuse — all revoked"}); return
		}
		if rec["exp"].(int64) < time.Now().Unix() { sendJSON(w, 401, map[string]string{"error": "Expired"}); return }
		rec["revoked"] = true
		newRt := newUUID() + newUUID()
		refreshTokens[sha256hash(newRt)] = map[string]any{"username": rec["username"], "family": rec["family"], "exp": time.Now().Unix() + 604800, "revoked": false}
		sendJSON(w, 200, map[string]any{"access_token": newUUID(), "refresh_token": newRt, "expires_in": 900})
	})

	mux.HandleFunc("/token-rotation", func(w http.ResponseWriter, r *http.Request) {
		sendHTML(w, pageHTML("Token Rotation", "<h2>Token Rotation</h2><p>Use client.</p>"), 200)
	})

	// Gateway
	mux.HandleFunc("/gateway/token", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		if users[r.FormValue("username")] != r.FormValue("password") { sendJSON(w, 401, map[string]string{"error": "Invalid"}); return }
		tok := newUUID()
		gatewayTokens[tok] = map[string]any{"username": r.FormValue("username"), "scopes": []string{"read", "write"}}
		sendJSON(w, 200, map[string]any{"access_token": tok})
	})

	mux.HandleFunc("/gateway/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		token := ""
		if strings.HasPrefix(auth, "Bearer ") { token = auth[7:] }
		rec := gatewayTokens[token]
		if rec == nil { sendJSON(w, 401, map[string]string{"error": "Invalid token"}); return }

		if strings.HasSuffix(r.URL.Path, "/validate") {
			sendJSON(w, 200, map[string]any{"active": true, "sub": rec["username"], "scopes": rec["scopes"]})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/resource") {
			sendJSON(w, 200, map[string]any{"message": fmt.Sprintf("Resource accessed by %s", rec["username"])})
			return
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Auth Patterns at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
