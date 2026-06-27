package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var users = map[string]string{
	"alice": getEnv("ALICE_PASSWORD", "password-alice"),
	"bob":   getEnv("BOB_PASSWORD", "password-bob"),
}

var (
	tickets  = make(map[string]map[string]any)
	sessions = make(map[string]string)
)

const serviceURL = "http://127.0.0.1:8000/protected"

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, body string, status int) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func sendText(w http.ResponseWriter, body string, status int) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func pageHTML(title, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">%s</body></html>`, body)
}

func redirect(w http.ResponseWriter, r *http.Request, location string) {
	http.Redirect(w, r, location, 302)
}

func parseForm(r *http.Request) {
	r.ParseForm()
}

func main() {
	mux := http.NewServeMux()

	// App: Home
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			sendHTML(w, "Not found", 404)
			return
		}
		sendHTML(w, pageHTML("CAS Demo", `
<h2>CAS Demo</h2>
<p>This app uses <strong>CAS</strong> for single sign-on.</p>
<p><a href="/protected">Protected resource</a></p>`), 200)
	})

	// App: Protected
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		ticket := r.URL.Query().Get("ticket")

		if ticket != "" {
			validateURL := fmt.Sprintf("http://127.0.0.1:8000/validate?ticket=%s&service=%s",
				url.QueryEscape(ticket), url.QueryEscape(serviceURL))

			resp, err := http.Get(validateURL)
			if err != nil {
				sendHTML(w, "Validation failed", 500)
				return
			}
			defer resp.Body.Close()

			buf := make([]byte, 1024)
			n, _ := resp.Body.Read(buf)
			text := strings.TrimSpace(string(buf[:n]))
			lines := strings.SplitN(text, "\n", 2)

			if lines[0] == "yes" {
				username := ""
				if len(lines) > 1 {
					username = strings.TrimSpace(lines[1])
				}
				sessionID := newUUID()
				sessions[sessionID] = username

				http.SetCookie(w, &http.Cookie{
					Name:     "session_id",
					Value:    sessionID,
					HttpOnly: true,
					SameSite: http.SameSiteLaxMode,
					Path:     "/",
				})
				redirect(w, r, "/protected")
				return
			}

			sendHTML(w, pageHTML("CAS Failed", fmt.Sprintf(`<h2>CAS Login Failed</h2><p>%s</p><p><a href="/">← Back</a></p>`, text)), 401)
			return
		}

		redirect(w, r, fmt.Sprintf("/login?service=%s", url.QueryEscape(serviceURL)))
	})

	// CAS: Login form
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			service := r.URL.Query().Get("service")
			errorMsg := r.URL.Query().Get("error")
			errHTML := ""
			if errorMsg != "" {
				errHTML = fmt.Sprintf(`<p style="color:red">%s</p>`, errorMsg)
			}

			sendHTML(w, pageHTML("CAS Login", fmt.Sprintf(`
<h2>CAS Login</h2>
%s
<form method="post" action="/login">
  <input type="hidden" name="service" value="%s">
  <p><label>Username: <input name="username" value="alice"></label></p>
  <p><label>Password: <input name="password" type="password"></label></p>
  <p><button type="submit">Login</button></p>
</form>`, errHTML, service)), 200)
			return
		}

		if r.Method == "POST" {
			parseForm(r)
			service := r.FormValue("service")
			username := r.FormValue("username")
			password := r.FormValue("password")

			if users[username] != password {
				redirect(w, r, fmt.Sprintf("/login?service=%s&error=Invalid+credentials", url.QueryEscape(service)))
				return
			}

			ticket := fmt.Sprintf("ST-%s", newUUID())
			tickets[ticket] = map[string]any{
				"username": username,
				"service":  service,
				"exp":      time.Now().Unix() + 300,
				"used":     false,
			}

			redirect(w, r, fmt.Sprintf("%s?ticket=%s", service, ticket))
			return
		}
	})

	// CAS: Validate
	mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		ticket := r.URL.Query().Get("ticket")
		service := r.URL.Query().Get("service")

		t, ok := tickets[ticket]
		if !ok {
			sendText(w, "no\nInvalid ticket", 200)
			return
		}
		if t["used"].(bool) {
			sendText(w, "no\nTicket already used", 200)
			return
		}
		if t["exp"].(int64) < time.Now().Unix() {
			sendText(w, "no\nTicket expired", 200)
			return
		}
		if t["service"].(string) != service {
			sendText(w, "no\nService mismatch", 200)
			return
		}

		t["used"] = true
		sendText(w, fmt.Sprintf("yes\n%s", t["username"]), 200)
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("CAS Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
