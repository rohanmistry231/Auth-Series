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

	"github.com/pquerna/otp/totp"
)

type user struct {
	Password    string
	MFASecret   string
	MFAEnabled  bool
	BackupCodes []string
}

var users = map[string]*user{
	"alice": {
		Password:   getEnv("ALICE_PASSWORD", "password-alice"),
		MFASecret:  "",
		MFAEnabled: false,
	},
}

var usedBackupCodes = make(map[string]bool)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
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
<h2>MFA Demo</h2>
<form method="post" action="/setup"><p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p><p><button type="submit">Setup MFA</button></p></form>
<hr>
<form method="post" action="/login"><p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><label>TOTP: <input name="totp"></label></p><p><button type="submit">Login</button></p></form></body></html>`, 200)
	})

	mux.HandleFunc("/setup", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		u := r.FormValue("username")
		p := r.FormValue("password")
		user, ok := users[u]
		if !ok || user.Password != p {
			sendJSON(w, 401, map[string]string{"error": "Invalid credentials"})
			return
		}

		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "AuthSeries MFA",
			AccountName: u,
		})
		if err != nil {
			sendJSON(w, 500, map[string]string{"error": "Failed to generate TOTP"})
			return
		}

		user.MFASecret = key.Secret()
		user.MFAEnabled = false

		sendJSON(w, 200, map[string]string{
			"secret":  key.Secret(),
			"qr_uri":  key.URL(),
			"message": "Scan QR with authenticator app",
		})
	})

	mux.HandleFunc("/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		u := r.FormValue("username")
		totpCode := r.FormValue("totp")
		user, ok := users[u]
		if !ok || user.MFASecret == "" {
			sendJSON(w, 400, map[string]string{"error": "MFA not setup"})
			return
		}

		valid := totp.Validate(totpCode, user.MFASecret)
		if !valid {
			sendJSON(w, 401, map[string]string{"error": "Invalid TOTP"})
			return
		}

		user.MFAEnabled = true
		codes := make([]string, 5)
		for i := range 5 {
			b := make([]byte, 4)
			rand.Read(b)
			codes[i] = strings.ToUpper(hex.EncodeToString(b))
		}
		user.BackupCodes = codes

		sendJSON(w, 200, map[string]any{
			"message":     "MFA enabled",
			"backup_codes": codes,
		})
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		u := r.FormValue("username")
		p := r.FormValue("password")
		totpCode := r.FormValue("totp")
		user, ok := users[u]
		if !ok || user.Password != p {
			sendJSON(w, 401, map[string]string{"error": "Invalid credentials"})
			return
		}

		if user.MFAEnabled {
			if totpCode == "" {
				sendJSON(w, 401, map[string]string{"error": "TOTP required"})
				return
			}
			if !totp.Validate(totpCode, user.MFASecret) {
				sendJSON(w, 401, map[string]string{"error": "Invalid TOTP"})
				return
			}
		}

		b := make([]byte, 16)
		rand.Read(b)
		token := hex.EncodeToString(b)

		sendJSON(w, 200, map[string]any{
			"access_token": token,
			"message":      fmt.Sprintf("Authenticated as %s", u),
		})
	})

	mux.HandleFunc("/recovery", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		u := r.FormValue("username")
		code := r.FormValue("backup_code")
		user, ok := users[u]
		if !ok {
			sendJSON(w, 401, map[string]string{"error": "Invalid username"})
			return
		}

		if usedBackupCodes[code] {
			sendJSON(w, 401, map[string]string{"error": "Code already used"})
			return
		}

		found := false
		for _, c := range user.BackupCodes {
			if c == code {
				found = true
				break
			}
		}
		if !found {
			sendJSON(w, 401, map[string]string{"error": "Invalid backup code"})
			return
		}

		usedBackupCodes[code] = true
		remaining := 0
		for _, c := range user.BackupCodes {
			if !usedBackupCodes[c] {
				remaining++
			}
		}

		b := make([]byte, 16)
		rand.Read(b)

		sendJSON(w, 200, map[string]any{
			"access_token":    hex.EncodeToString(b),
			"message":         fmt.Sprintf("Recovery login as %s", u),
			"codes_remaining": remaining,
		})
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("MFA Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
