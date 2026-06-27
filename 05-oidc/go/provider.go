package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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
	idTokenTTL  = 3600
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

type userProfile struct {
	Password       string
	Sub            string
	Name           string
	GivenName      string
	FamilyName     string
	Email          string
	EmailVerified  bool
	Picture        string
}

var users = map[string]*userProfile{
	"alice": {
		Password:      getEnv("ALICE_PASSWORD", "password-alice"),
		Sub:           "user-alice-001",
		Name:          "Alice Johnson",
		GivenName:     "Alice",
		FamilyName:    "Johnson",
		Email:         "alice@example.com",
		EmailVerified: true,
		Picture:       "https://example.com/avatars/alice.jpg",
	},
	"bob": {
		Password:      getEnv("BOB_PASSWORD", "password-bob"),
		Sub:           "user-bob-002",
		Name:          "Bob Smith",
		GivenName:     "Bob",
		FamilyName:    "Smith",
		Email:         "bob@example.com",
		EmailVerified: false,
		Picture:       "https://example.com/avatars/bob.jpg",
	},
}

type client struct {
	ClientSecret string
	RedirectURIs []string
	GrantTypes   []string
}

var clients = map[string]*client{
	"rp":  {ClientSecret: getEnv("RP_SECRET", "rp-secret"), RedirectURIs: []string{"http://localhost:8001/callback"}, GrantTypes: []string{"authorization_code", "refresh_token"}},
	"spa": {RedirectURIs: []string{"http://localhost:3000/callback"}, GrantTypes: []string{"authorization_code"}},
}

type authCodeStore struct {
	ClientID    string
	RedirectURI string
	Scope       string
	Nonce       string
	Username    string
	AuthTime    int64
	Expires     time.Time
}

type refreshEntry struct {
	ClientID string
	Username string
	Scope    string
	Expires  time.Time
}

var (
	authCodes    = make(map[string]*authCodeStore)
	refreshStore = make(map[string]*refreshEntry)
	mu           sync.RWMutex
)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func randomToken() string {
	b := make([]byte, 36)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func makeIDToken(user *userProfile, clientID, nonce string, authTime int64) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer, "sub": user.Sub, "aud": []string{clientID},
		"exp": now.Add(time.Duration(idTokenTTL) * time.Second).Unix(), "iat": now.Unix(),
		"auth_time": authTime, "azp": clientID, "name": user.Name,
		"given_name": user.GivenName, "family_name": user.FamilyName,
		"email": user.Email, "email_verified": user.EmailVerified, "picture": user.Picture,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "oidc-rsa-1"
	signed, _ := token.SignedString(rsaPrivateKey)
	return signed
}

func makeAccessToken(user *userProfile, scope, clientID string) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": issuer, "sub": user.Sub, "client_id": clientID, "scope": scope,
		"iat": now.Unix(), "exp": now.Add(time.Duration(accessTTL) * time.Second).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, _ := token.SignedString(rsaPrivateKey)
	return signed
}

func extractScopeClaims(scope string, user *userProfile) map[string]any {
	r := map[string]any{"sub": user.Sub}
	if strings.Contains(scope, "profile") {
		r["name"] = user.Name
		r["given_name"] = user.GivenName
		r["family_name"] = user.FamilyName
		r["picture"] = user.Picture
	}
	if strings.Contains(scope, "email") {
		r["email"] = user.Email
		r["email_verified"] = user.EmailVerified
	}
	return r
}

func sendJSON(w http.ResponseWriter, s int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(s)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, h string) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(h))
}

func authorizeHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	cl, ok := clients[q.Get("client_id")]
	if !ok {
		sendJSON(w, 400, map[string]string{"error": "invalid_client"})
		return
	}
	validURI := false
	for _, u := range cl.RedirectURIs {
		if u == q.Get("redirect_uri") {
			validURI = true
			break
		}
	}
	if !validURI || q.Get("response_type") != "code" {
		sendJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		sendJSON(w, 400, map[string]string{"error": "openid_scope_required"})
		return
	}
	sendHTML(w, fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>Sign in</h2>
<form method="post" action="/consent">
<input type="hidden" name="response_type" value="%s">
<input type="hidden" name="client_id" value="%s">
<input type="hidden" name="redirect_uri" value="%s">
<input type="hidden" name="scope" value="%s">
<input type="hidden" name="state" value="%s">
<input type="hidden" name="nonce" value="%s">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit" name="approve" value="yes">Sign In</button>
<button type="submit" name="approve" value="no">Cancel</button></p>
</form></body></html>`,
		q.Get("response_type"), q.Get("client_id"), q.Get("redirect_uri"),
		q.Get("scope"), q.Get("state"), q.Get("nonce")))
}

func consentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, 405, map[string]string{"error": "method_not_allowed"})
		return
	}
	r.ParseForm()
	if r.FormValue("approve") != "yes" {
		sendJSON(w, 403, map[string]string{"error": "access_denied"})
		return
	}
	user, ok := users[r.FormValue("username")]
	if !ok || user.Password != r.FormValue("password") {
		sendJSON(w, 401, map[string]string{"error": "invalid_credentials"})
		return
	}
	code := randomToken()
	authTime := time.Now().Unix()
	mu.Lock()
	authCodes[code] = &authCodeStore{
		ClientID: r.FormValue("client_id"), RedirectURI: r.FormValue("redirect_uri"),
		Scope: r.FormValue("scope"), Nonce: r.FormValue("nonce"),
		Username: r.FormValue("username"), AuthTime: authTime,
		Expires: time.Now().Add(time.Duration(authCodeTTL) * time.Second),
	}
	mu.Unlock()
	v := url.Values{"code": {code}}
	if s := r.FormValue("state"); s != "" {
		v.Set("state", s)
	}
	http.Redirect(w, r, r.FormValue("redirect_uri")+"?"+v.Encode(), http.StatusFound)
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSON(w, 405, map[string]string{"error": "method_not_allowed"})
		return
	}
	r.ParseForm()
	switch r.FormValue("grant_type") {
	case "authorization_code":
		handleAuthCode(w, r)
	case "refresh_token":
		handleRefresh(w, r)
	default:
		sendJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
	}
}

func handleAuthCode(w http.ResponseWriter, r *http.Request) {
	cl, ok := clients[r.FormValue("client_id")]
	if !ok || (cl.ClientSecret != "" && cl.ClientSecret != r.FormValue("client_secret")) {
		sendJSON(w, 400, map[string]string{"error": "invalid_client"})
		return
	}
	mu.Lock()
	stored, exists := authCodes[r.FormValue("code")]
	if exists {
		delete(authCodes, r.FormValue("code"))
	}
	mu.Unlock()
	if !exists || time.Now().After(stored.Expires) ||
		stored.ClientID != r.FormValue("client_id") ||
		stored.RedirectURI != r.FormValue("redirect_uri") {
		sendJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	user, _ := users[stored.Username]
	scope := stored.Scope
	at := makeAccessToken(user, scope, r.FormValue("client_id"))
	id := makeIDToken(user, r.FormValue("client_id"), stored.Nonce, stored.AuthTime)
	rt := randomToken()
	mu.Lock()
	refreshStore[rt] = &refreshEntry{ClientID: r.FormValue("client_id"), Username: stored.Username, Scope: scope, Expires: time.Now().Add(time.Duration(refreshTTL) * time.Second)}
	mu.Unlock()
	sendJSON(w, 200, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": accessTTL, "refresh_token": rt, "id_token": id, "scope": scope})
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	stored, exists := refreshStore[r.FormValue("refresh_token")]
	if exists {
		delete(refreshStore, r.FormValue("refresh_token"))
	}
	mu.Unlock()
	if !exists || time.Now().After(stored.Expires) || stored.ClientID != r.FormValue("client_id") {
		sendJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	user, _ := users[stored.Username]
	at := makeAccessToken(user, stored.Scope, r.FormValue("client_id"))
	id := makeIDToken(user, r.FormValue("client_id"), "", time.Now().Unix())
	rt := randomToken()
	mu.Lock()
	refreshStore[rt] = &refreshEntry{ClientID: r.FormValue("client_id"), Username: stored.Username, Scope: stored.Scope, Expires: time.Now().Add(time.Duration(refreshTTL) * time.Second)}
	mu.Unlock()
	sendJSON(w, 200, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": accessTTL, "refresh_token": rt, "id_token": id, "scope": stored.Scope})
}

func userinfoHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		sendJSON(w, 401, map[string]string{"error": "missing_token"})
		return
	}
	token, err := jwt.Parse(strings.TrimPrefix(auth, "Bearer "), func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method")
		}
		return rsaPublicKey, nil
	})
	if err != nil {
		sendJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		sendJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	for _, u := range users {
		if u.Sub == sub {
			sendJSON(w, 200, extractScopeClaims(scope, u))
			return
		}
	}
	sendJSON(w, 404, map[string]string{"error": "user_not_found"})
}

func discoveryHandler(w http.ResponseWriter, r *http.Request) {
	sendJSON(w, 200, map[string]any{
		"issuer":                               issuer,
		"authorization_endpoint":               issuer + "/authorize",
		"token_endpoint":                       issuer + "/token",
		"userinfo_endpoint":                    issuer + "/userinfo",
		"jwks_uri":                             issuer + "/.well-known/jwks.json",
		"scopes_supported":                     []string{"openid", "profile", "email"},
		"response_types_supported":             []string{"code"},
		"grant_types_supported":                []string{"authorization_code", "refresh_token"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	n := base64.RawURLEncoding.EncodeToString(rsaPublicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString([]byte{byte(rsaPublicKey.E >> 16), byte(rsaPublicKey.E >> 8), byte(rsaPublicKey.E)})
	sendJSON(w, 200, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "oidc-rsa-1", "n": n, "e": e,
		}},
	})
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", authorizeHandler)
	mux.HandleFunc("/consent", consentHandler)
	mux.HandleFunc("/token", tokenHandler)
	mux.HandleFunc("/userinfo", userinfoHandler)
	mux.HandleFunc("/.well-known/openid-configuration", discoveryHandler)
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)

	addr := fmt.Sprintf("0.0.0.0:%s", getEnv("PORT", "8000"))
	log.Printf("OIDC Provider at http://localhost:%s", getEnv("PORT", "8000"))
	log.Fatal(http.ListenAndServe(addr, mux))
}

var _ = sha256.New
