package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	appID     = getEnv("APP_ID", "app1")
	appPort   = getEnv("APP_PORT", "8001")
	appName   = getEnv("APP_NAME", "My App")
	ssoServer = getEnv("SSO_SERVER", "http://localhost:8000")
)

type session struct {
	Username string `json:"username"`
	AppID    string `json:"app_id"`
}

var localSessions = make(map[string]*session)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func sendHTML(w http.ResponseWriter, s string, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write([]byte(s))
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Path: "/"})
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("app_session")
		if err != nil || localSessions[cookie.Value] == nil {
			http.Redirect(w, r, fmt.Sprintf("%s/sso/login?redirect=http://localhost:%s/sso/callback", ssoServer, appPort), http.StatusFound)
			return
		}
		sess := localSessions[cookie.Value]
		sendHTML(w, fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>%s</h2>
<p>Logged in as: <strong>%s</strong></p>
<p>App ID: %s</p>
<hr>
<p><a href="/profile">Profile</a> | <a href="/logout">Logout</a></p>
</body></html>`, appName, sess.Username, appID), 200)
	})

	mux.HandleFunc("/sso/callback", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		resp, err := http.Get(fmt.Sprintf("%s/sso/validate?token=%s", ssoServer, token))
		if err != nil || resp.StatusCode != 200 {
			sendHTML(w, "SSO validation failed", 401)
			return
		}
		var data map[string]any
		body, _ := io.ReadAll(resp.Body)
		json.Unmarshal(body, &data)
		resp.Body.Close()

		username, _ := data["sub"].(string)
		sessionID := fmt.Sprintf("%x", time.Now().UnixNano())[:16]
		localSessions[sessionID] = &session{Username: username, AppID: appID}
		setCookie(w, "app_session", sessionID, 86400)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	mux.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("app_session")
		if err != nil || localSessions[cookie.Value] == nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		sess := localSessions[cookie.Value]
		sid := cookie.Value
		if len(sid) > 8 {
			sid = sid[:8]
		}
		sendHTML(w, fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Profile</h2>
<table border="1" cellpadding="8" style="border-collapse:collapse">
<tr><td>Username</td><td>%s</td></tr>
<tr><td>App</td><td>%s</td></tr>
<tr><td>Session</td><td>%s...</td></tr>
</table>
<p><a href="/dashboard">Back</a></p>`, sess.Username, appName, sid), 200)
	})

	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie("app_session"); err == nil {
			delete(localSessions, cookie.Value)
		}
		setCookie(w, "app_session", "", 0)
		sendHTML(w, fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>Logged out of %s</h2>
<p><a href="%s/sso/logout">Logout of all apps</a></p>
<p><a href="/dashboard">Login again</a></p>
</body></html>`, appName, ssoServer), 200)
	})

	addr := fmt.Sprintf("0.0.0.0:%s", appPort)
	log.Printf("%s at http://localhost:%s", appName, appPort)
	log.Fatal(http.ListenAndServe(addr, mux))
}

import "time"
var _ = strings.TrimSpace
