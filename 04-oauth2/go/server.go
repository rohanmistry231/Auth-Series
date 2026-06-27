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
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	issuer      = "http://localhost:8000"
	accessTTL   = 3600
	refreshTTL  = 86400 * 7
	authCodeTTL = 300
)

var rsaPrivateKey *rsa.PrivateKey
var rsaPublicKey *rsa.PublicKey

func init() {
	var err error
	rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}
	rsaPublicKey = &rsaPrivateKey.PublicKey
}

var users = map[string]string{
	"alice": getEnv("ALICE_PASSWORD", "password-alice"),
	"bob":   getEnv("BOB_PASSWORD", "password-bob"),
}

type client struct {
	ClientSecret  string
	RedirectURIs  []string
	GrantTypes    []string
}

var clients = map[string]client{
	"webapp": {
		ClientSecret: getEnv("WEBAPP_SECRET", "webapp-secret"),
		RedirectURIs: []string{"http://localhost:8001/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	},
	"spa": {
		RedirectURIs: []string{"http://localhost:3000/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	},
	"service-a": {
		ClientSecret: getEnv("SERVICE_A_SECRET", "service-a-secret"),
		GrantTypes:   []string{"client_credentials"},
	},
}

type authCode struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	Username            string
	Expires             time.Time
	CodeChallenge       string
	CodeChallengeMethod string
}

type refreshEntry struct {
	ClientID string
	Username string
	Scope    string
	Expires  time.Time
}

type deviceEntry struct {
	ClientID string
	Scope    string
	UserCode string
	Status   string
	Username string
	Expires  time.Time
}

var (
	authCodes    = make(map[string]*authCode)
	refreshStore = make(map[string]*refreshEntry)
	deviceStore  = make(map[string]*deviceEntry)
	mu           sync.RWMutex
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func randomToken() string {
	b := make([]byte, 36)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func makeAccessToken(sub, scope, clientID string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       issuer,
		"sub":       sub,
		"client_id": clientID,
		"scope":     scope,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(accessTTL) * time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, _ := token.SignedString(rsaPrivateKey)
	return signed
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, html string) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(html))
}

func parseForm(r *http.Request) url.Values {
	r.ParseForm()
	return r.Form
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	responseType := q.Get("response_type")
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	scope := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")

	cl, exists := clients[clientID]
	if !exists {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}

	validURI := false
	for _, uri := range cl.RedirectURIs {
		if uri == redirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_redirect_uri"})
		return
	}
	if responseType != "code" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_response_type"})
		return
	}
	if codeChallenge != "" && codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_code_challenge_method"})
		return
	}

	sendHTML(w, fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Authorize <code>%s</code></h2>
<form method="post" action="/consent">
<input type="hidden" name="response_type" value="%s">
<input type="hidden" name="client_id" value="%s">
<input type="hidden" name="redirect_uri" value="%s">
<input type="hidden" name="scope" value="%s">
<input type="hidden" name="state" value="%s">
<input type="hidden" name="code_challenge" value="%s">
<input type="hidden" name="code_challenge_method" value="%s">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password" value="password-alice"></label></p>
<p><button type="submit" name="approve" value="yes">Approve</button>
<button type="submit" name="approve" value="no">Deny</button></p>
</form></body></html>`,
		clientID, responseType, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod))
}

func consentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	r.ParseForm()
	approve := r.FormValue("approve")
	if approve != "yes" {
		sendJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied"})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	expected, exists := users[username]
	if !exists || expected != password {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}

	code := randomToken()

	mu.Lock()
	authCodes[code] = &authCode{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		Username:            username,
		Expires:             time.Now().Add(time.Duration(authCodeTTL) * time.Second),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
	}
	mu.Unlock()

	v := url.Values{}
	v.Set("code", code)
	if s := r.FormValue("state"); s != "" {
		v.Set("state", s)
	}
	http.Redirect(w, r, r.FormValue("redirect_uri")+"?"+v.Encode(), http.StatusFound)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	r.ParseForm()
	grantType := r.FormValue("grant_type")

	switch grantType {
	case "authorization_code":
		handleAuthCode(w, r)
	case "client_credentials":
		handleClientCreds(w, r)
	case "refresh_token":
		handleRefresh(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		handleDeviceToken(w, r)
	default:
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
	}
}

func handleAuthCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	cl, exists := clients[clientID]
	if !exists {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}
	if cl.ClientSecret != "" && cl.ClientSecret != clientSecret {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client_secret"})
		return
	}

	mu.Lock()
	stored, exists := authCodes[code]
	if exists {
		delete(authCodes, code)
	}
	mu.Unlock()

	if !exists || time.Now().After(stored.Expires) || stored.ClientID != clientID || stored.RedirectURI != redirectURI {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	if stored.CodeChallenge != "" {
		if codeVerifier == "" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "code_verifier_required"})
			return
		}
		if stored.CodeChallengeMethod == "S256" {
			h := sha256.Sum256([]byte(codeVerifier))
			expected := base64.RawURLEncoding.EncodeToString(h[:])
			if expected != stored.CodeChallenge {
				sendJSON(w, http.StatusBadRequest, map[string]string{"error": "pkce_mismatch"})
				return
			}
		} else if codeVerifier != stored.CodeChallenge {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "pkce_mismatch"})
			return
		}
	}

	accessToken := makeAccessToken(stored.Username, stored.Scope, clientID)
	refreshToken := randomToken()

	mu.Lock()
	refreshStore[refreshToken] = &refreshEntry{
		ClientID: clientID,
		Username: stored.Username,
		Scope:    stored.Scope,
		Expires:  time.Now().Add(time.Duration(refreshTTL) * time.Second),
	}
	mu.Unlock()

	sendJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    accessTTL,
		"refresh_token": refreshToken,
		"scope":         stored.Scope,
	})
}

func handleClientCreds(w http.ResponseWriter, r *http.Request) {
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")
	scope := r.FormValue("scope")

	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Basic ") {
		decoded, err := base64.StdEncoding.DecodeString(auth[6:])
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				clientID, clientSecret = parts[0], parts[1]
			}
		}
	}

	cl, exists := clients[clientID]
	if !exists || (cl.ClientSecret != "" && cl.ClientSecret != clientSecret) {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	accessToken := makeAccessToken(clientID, scope, clientID)
	sendJSON(w, http.StatusOK, map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   accessTTL,
		"scope":        scope,
	})
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := r.FormValue("refresh_token")
	clientID := r.FormValue("client_id")

	mu.Lock()
	stored, exists := refreshStore[refreshToken]
	if exists {
		delete(refreshStore, refreshToken)
	}
	mu.Unlock()

	if !exists || time.Now().After(stored.Expires) || stored.ClientID != clientID {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	newAccess := makeAccessToken(stored.Username, stored.Scope, clientID)
	newRefresh := randomToken()

	mu.Lock()
	refreshStore[newRefresh] = &refreshEntry{
		ClientID: clientID,
		Username: stored.Username,
		Scope:    stored.Scope,
		Expires:  time.Now().Add(time.Duration(refreshTTL) * time.Second),
	}
	mu.Unlock()

	sendJSON(w, http.StatusOK, map[string]any{
		"access_token":  newAccess,
		"token_type":    "Bearer",
		"expires_in":    accessTTL,
		"refresh_token": newRefresh,
		"scope":         stored.Scope,
	})
}

func handleDeviceToken(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.FormValue("device_code")

	mu.RLock()
	stored, exists := deviceStore[deviceCode]
	mu.RUnlock()

	if !exists || time.Now().After(stored.Expires) {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	if stored.Status == "pending" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "authorization_pending"})
		return
	}

	if stored.Status == "approved" {
		mu.Lock()
		delete(deviceStore, deviceCode)
		mu.Unlock()

		sendJSON(w, http.StatusOK, map[string]any{
			"access_token":  makeAccessToken(stored.Username, stored.Scope, stored.ClientID),
			"token_type":    "Bearer",
			"expires_in":    accessTTL,
			"refresh_token": randomToken(),
		})
		return
	}

	sendJSON(w, http.StatusBadRequest, map[string]string{"error": "expired_token"})
}

func deviceCodeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	r.ParseForm()
	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")

	if _, exists := clients[clientID]; !exists {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}

	deviceCode := randomToken()
	userCodeBytes := make([]byte, 3)
	rand.Read(userCodeBytes)
	userCode := fmt.Sprintf("%X", userCodeBytes)[:8]

	mu.Lock()
	deviceStore[deviceCode] = &deviceEntry{
		ClientID: clientID,
		Scope:    scope,
		UserCode: userCode,
		Status:   "pending",
		Expires:  time.Now().Add(600 * time.Second),
	}
	mu.Unlock()

	sendJSON(w, http.StatusOK, map[string]any{
		"device_code":              deviceCode,
		"user_code":                userCode,
		"verification_uri":         issuer + "/device",
		"verification_uri_complete": issuer + "/device?user_code=" + userCode,
		"expires_in":               600,
		"interval":                 5,
	})
}

func deviceApproveHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	userCode := r.FormValue("user_code")
	username := r.FormValue("username")
	password := r.FormValue("password")

	expected, exists := users[username]
	if !exists || expected != password {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}

	mu.Lock()
	for _, entry := range deviceStore {
		if entry.UserCode == userCode && entry.Status == "pending" {
			entry.Status = "approved"
			entry.Username = username
			mu.Unlock()
			sendJSON(w, http.StatusOK, map[string]string{"message": "Device approved"})
			return
		}
	}
	mu.Unlock()

	sendJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_user_code"})
}

func deviceFormHandler(w http.ResponseWriter, r *http.Request) {
	sendHTML(w, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>Device Authorization</h2>
<form method="post" action="/device/approve">
<p><label>User Code: <input name="user_code" size="10" autofocus></label></p>
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password" value="password-alice"></label></p>
<p><button type="submit">Approve</button></p>
</form></body></html>`)
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_token"})
		return
	}

	tokenStr := strings.TrimPrefix(auth, "Bearer ")
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return rsaPublicKey, nil
	})
	if err != nil {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}

	sendJSON(w, http.StatusOK, map[string]any{
		"sub":   claims["sub"],
		"scope": claims["scope"],
	})
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	pubBytes, _ := x509.MarshalPKIXPublicKey(rsaPublicKey)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	_ = pubPEM

	n := base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{byte(rsaPublicKey.E >> 16), byte(rsaPublicKey.E >> 8), byte(rsaPublicKey.E)})

	sendJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": "auth-series-rsa-1",
			"n":   n,
			"e":   e,
		}},
	})
}

func wellKnownHandler(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, http.StatusOK, map[string]any{
		"issuer":                            issuer,
		"authorization_endpoint":            issuer + "/authorize",
		"token_endpoint":                    issuer + "/token",
		"device_authorization_endpoint":     issuer + "/device/code",
		"userinfo_endpoint":                 issuer + "/userinfo",
		"response_types_supported":          []string{"code"},
		"grant_types_supported":             []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"},
		"code_challenge_methods_supported":  []string{"S256", "plain"},
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", authorizeHandler)
	mux.HandleFunc("/consent", consentHandler)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/device/code", deviceCodeHandler)
	mux.HandleFunc("/device/approve", deviceApproveHandler)
	mux.HandleFunc("/device", deviceFormHandler)
	mux.HandleFunc("/userinfo", userinfoHandler)
	mux.HandleFunc("/.well-known/oauth-authorization-server", wellKnownHandler)

	addr := fmt.Sprintf("0.0.0.0:%s", getEnv("PORT", "8000"))
	log.Printf("OAuth 2.0 Server running at http://localhost:%s", getEnv("PORT", "8000"))
	log.Fatal(http.ListenAndServe(addr, mux))
}

var _ = crypto.SHA256
