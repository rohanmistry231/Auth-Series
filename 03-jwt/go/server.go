package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	accessTTL  = 15 * time.Minute
	refreshTTL = 7 * 24 * time.Hour
	issuer     = "auth-series"
)

var hs256Secret = []byte(getEnv("JWT_HS256_SECRET", "change-me-to-a-256-bit-secret-in-production"))

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

type refreshEntry struct {
	Sub string
	Exp int64
}

var (
	refreshStore = make(map[string]refreshEntry)
	refreshMu    sync.RWMutex
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// ---------------------------------------------------------------------------
// Token generation
// ---------------------------------------------------------------------------

func makeAccessToken(sub, role string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":  issuer,
		"sub":  sub,
		"role": role,
		"iat":  now.Unix(),
		"exp":  now.Add(accessTTL).Unix(),
		"type": "access",
		"jti":  fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d%x", now.UnixNano(), sub)))),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(rsaPrivateKey)
}

func makeRefreshToken(sub string) (string, error) {
	now := time.Now()
	exp := now.Add(refreshTTL).Unix()

	jti := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("refresh-%d-%s", now.UnixNano(), sub))))

	claims := jwt.MapClaims{
		"iss":  issuer,
		"sub":  sub,
		"iat":  now.Unix(),
		"exp":  exp,
		"type": "refresh",
		"jti":  jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(hs256Secret)
	if err != nil {
		return "", err
	}

	refreshMu.Lock()
	refreshStore[jti] = refreshEntry{Sub: sub, Exp: exp}
	refreshMu.Unlock()

	return signed, nil
}

func rotateRefresh(oldJTI, sub string) (string, error) {
	refreshMu.Lock()
	delete(refreshStore, oldJTI)
	refreshMu.Unlock()
	return makeRefreshToken(sub)
}

// ---------------------------------------------------------------------------
// Token validation
// ---------------------------------------------------------------------------

func verifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			return rsaPublicKey, nil
		}
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			return hs256Secret, nil
		}
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	tokenType, _ := claims["type"].(string)
	if tokenType != "access" {
		return nil, fmt.Errorf("wrong token type: %s", tokenType)
	}

	iss, _ := claims["iss"].(string)
	if iss != issuer {
		return nil, fmt.Errorf("wrong issuer: %s", iss)
	}

	return claims, nil
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var data struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	expected, exists := users[data.Username]
	if !exists || expected != data.Password {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid credentials"})
		return
	}

	role := map[bool]string{true: "admin", false: "user"}[data.Username == "alice"]

	accessToken, err := makeAccessToken(data.Username, role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
		return
	}

	refreshToken, err := makeRefreshToken(data.Username)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate refresh token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	})
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Missing or malformed Authorization header"})
		return
	}

	token := strings.TrimPrefix(auth, "Bearer ")
	claims, err := verifyAccessToken(token)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid or expired access token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"sub":     claims["sub"],
		"role":    claims["role"],
		"message": "You have accessed a protected resource via JWT",
	})
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	var data struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil || data.RefreshToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Missing refresh_token"})
		return
	}

	token, err := jwt.Parse(data.RefreshToken, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return hs256Secret, nil
	})
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid refresh token"})
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid refresh token"})
		return
	}

	tokenType, _ := claims["type"].(string)
	if tokenType != "refresh" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Wrong token type"})
		return
	}

	jti, _ := claims["jti"].(string)

	refreshMu.RLock()
	stored, exists := refreshStore[jti]
	refreshMu.RUnlock()

	if !exists {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Refresh token has been revoked"})
		return
	}

	sub := stored.Sub
	role := map[bool]string{true: "admin", false: "user"}[sub == "alice"]

	accessToken, err := makeAccessToken(sub, role)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate token"})
		return
	}

	newRefresh, err := rotateRefresh(jti, sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to generate refresh token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": newRefresh,
	})
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	pubBytes := x509.MarshalPKCS1PublicKey(rsaPublicKey)
	n := rsaPublicKey.N.Bytes()
	e := rsaPublicKey.E

	nB64 := base64.RawURLEncoding.EncodeToString(n)
	eB64 := base64.RawURLEncoding.EncodeToString([]byte{byte(e >> 16), byte(e >> 8), byte(e)})

	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]string{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": "auth-series-rsa-1",
			"n":   nB64,
			"e":   eB64,
		}},
	})
	_ = pubBytes
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/protected", protectedHandler)
	mux.HandleFunc("/refresh", refreshHandler)
	mux.HandleFunc("/.well-known/jwks.json", jwksHandler)

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Server running at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
