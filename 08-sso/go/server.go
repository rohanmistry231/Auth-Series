package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	ssoSecret = getEnv("SSO_SECRET", "sso-secret-change-me")
	ssoDomain = "http://localhost:8000"
	tokenTTL  = 60
	ssoKey    *rsa.PrivateKey
	ssoPub    *rsa.PublicKey
)

func init() {
	var err error
	ssoKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	ssoPub = &ssoKey.PublicKey
}

var users = map[string]string{
	"alice": getEnv("ALICE_PASSWORD", "password-alice"),
	"bob":   getEnv("BOB_PASSWORD", "password-bob"),
}

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func makeSSOToken(username string) string {
	now := time.Now().Unix()
	header := `{"alg":"RS256","typ":"JWT"}`
	payload := fmt.Sprintf(`{"iss":"%s","sub":"%s","iat":%d,"exp":%d,"type":"sso"}`, ssoDomain, username, now, now+int64(tokenTTL))
	h := base64.RawURLEncoding.EncodeToString([]byte(header))
	p := base64.RawURLEncoding.EncodeToString([]byte(payload))
	hash := sha256.Sum256([]byte(h + "." + p))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, ssoKey, crypto.SHA256, hash[:])
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func verifySSOToken(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(ssoPub, crypto.SHA256, hash[:], sig); err != nil {
		return nil, false
	}
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)
	if payload["iss"] != ssoDomain || payload["type"] != "sso" {
		return nil, false
	}
	exp, _ := payload["exp"].(float64)
	if int64(exp) < time.Now().Unix() {
		return nil, false
	}
	return payload, true
}

func sendHTML(w http.ResponseWriter, s string, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write([]byte(s))
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge, Path: "/"})
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/sso/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			redirect := r.URL.Query().Get("redirect")
			sendHTML(w, fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>SSO Login</h2>
<form method="post" action="/sso/login">
<input type="hidden" name="redirect" value="%s">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Sign In</button></p>
</form></body></html>`, redirect), 200)
			return
		}
		if r.Method == http.MethodPost {
			r.ParseForm()
			u := r.FormValue("username")
			p := r.FormValue("password")
			expected, ok := users[u]
			if !ok || expected != p {
				sendHTML(w, "Invalid credentials", 401)
				return
			}
			token := makeSSOToken(u)
			setCookie(w, "sso_session", token, 86400)
			redirect := r.FormValue("redirect")
			http.Redirect(w, r, redirect+"?token="+url.QueryEscape(token), http.StatusFound)
			return
		}
	})

	mux.HandleFunc("/sso/validate", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		payload, ok := verifySSOToken(token)
		if !ok {
			sendJSON(w, 401, map[string]string{"error": "Invalid token"})
			return
		}
		sendJSON(w, 200, map[string]any{"sub": payload["sub"], "valid": true})
	})

	mux.HandleFunc("/sso/check", func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("sso_session")
		if err != nil {
			sendJSON(w, 401, map[string]string{"error": "No SSO session"})
			return
		}
		payload, ok := verifySSOToken(cookie.Value)
		if !ok {
			sendJSON(w, 401, map[string]string{"error": "Invalid SSO session"})
			return
		}
		sendJSON(w, 200, map[string]any{"sub": payload["sub"], "valid": true})
	})

	mux.HandleFunc("/sso/logout", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sso_session", Value: "", HttpOnly: true, MaxAge: -1, Path: "/"})
		sendHTML(w, "<h2>Logged out of SSO</h2>", 200)
	})

	addr := fmt.Sprintf("0.0.0.0:%s", getEnv("PORT", "8000"))
	log.Printf("SSO Server at http://localhost:%s", getEnv("PORT", "8000"))
	log.Fatal(http.ListenAndServe(addr, mux))
}

var (
	_ = x509.CreateCertificate
	_ = pem.EncodeToMemory
	_ = crypto.SHA256
)
