package main

import (
	"crypto/rand"
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
	rateLimitStore = make(map[string][]int64)
	auditLog       []map[string]any
)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" { return v }
	return f
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func rateLimit(key string, max int, windowMs int64) bool {
	now := time.Now().UnixMilli()
	rateLimitStore[key] = filter(rateLimitStore[key], func(t int64) bool { return t > now-windowMs })
	if len(rateLimitStore[key]) >= max { return false }
	rateLimitStore[key] = append(rateLimitStore[key], now)
	return true
}

func filter(slice []int64, fn func(int64) bool) []int64 {
	var r []int64
	for _, v := range slice { if fn(v) { r = append(r, v) } }
	return r
}

func logAuthEvent(event, username, ip string, success bool, details string) {
	entry := map[string]any{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"event": event, "username": username, "ip": ip,
		"success": success, "details": details,
	}
	auditLog = append(auditLog, entry)
	b, _ := json.Marshal(entry)
	fmt.Printf("  [AUDIT] %s\n", string(b))
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, body string, status int) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
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
		sendHTML(w, pageHTML("Security Demo", `
<h2>Security Best Practices Demo</h2>
<ul>
  <li><a href="/login">Login (rate limited)</a></li>
  <li><a href="/audit-log">Audit Log</a></li>
  <li>Security headers on all responses</li>
</ul>`), 200)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.Split(r.RemoteAddr, ":")[0]

		if r.Method == "GET" {
			if !rateLimit("page:"+ip, 20, 60000) { sendJSON(w, 429, map[string]string{"error": "Rate limited"}); return }
			sendHTML(w, pageHTML("Login", `
<h2>Login (Rate Limited)</h2>
<form method="post" action="/login"><p><label>User: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p><p><button type="submit">Login</button></p></form>`), 200)
			return
		}

		if r.Method == "POST" {
			if !rateLimit("login:"+ip, 5, 60000) { sendJSON(w, 429, map[string]string{"error": "Rate limited"}); return }
			parseForm(r)
			u, p := r.FormValue("username"), r.FormValue("password")

			if users[u] != p {
				logAuthEvent("LOGIN_FAILURE", u, ip, false, "Invalid password")
				sendJSON(w, 401, map[string]string{"error": "Invalid credentials"})
				return
			}

			sid := newUUID()
			logAuthEvent("LOGIN_SUCCESS", u, ip, true, fmt.Sprintf("Session %s...", sid[:16]))

			http.SetCookie(w, &http.Cookie{
				Name: "session_id", Value: sid, HttpOnly: true, SameSite: http.SameSiteStrictMode, Path: "/",
			})
			sendHTML(w, pageHTML("Welcome", fmt.Sprintf(`
<h2>Welcome, %s!</h2>
<p>Session: <code>%s...</code></p>
<p><a href="/audit-log">View Audit Log</a></p>`, u, sid[:16])), 200)
		}
	})

	mux.HandleFunc("/audit-log", func(w http.ResponseWriter, r *http.Request) {
		entries := ""
		start := len(auditLog) - 20
		if start < 0 { start = 0 }
		for _, e := range auditLog[start:] {
			ts, _ := e["timestamp"].(string)
			ev, _ := e["event"].(string)
			un, _ := e["username"].(string)
			succ, _ := e["success"].(bool)
			det, _ := e["details"].(string)
			icon := "❌"
			if succ { icon = "✅" }
			entries += fmt.Sprintf(`<li><code>%s</code> <strong>%s</strong> %s — %s<br><small>%s</small></li>`, ts[:19], icon, ev, un, det)
		}
		if entries == "" { entries = "<li>No events</li>" }
		sendHTML(w, pageHTML("Audit Log", fmt.Sprintf(`
<h2>Audit Log (last 20)</h2>
<ul style="list-style:none;padding:0">%s</ul>
<p><a href="/">← Back</a></p>`, entries)), 200)
	})

	mux.HandleFunc("/check-headers", func(w http.ResponseWriter, r *http.Request) {
		sendJSON(w, 200, map[string]any{
			"message": "Security headers on all responses",
			"headers": []string{"HSTS", "X-Content-Type-Options", "X-Frame-Options"},
		})
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Security Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
