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
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var (
	issuer       = getEnv("OIDC_ISSUER", "http://localhost:8000")
	clientID     = "rp"
	clientSecret = getEnv("RP_SECRET", "rp-secret")
	redirectURI  = "http://localhost:8001/callback"
)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

type discovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JWKSUri                          string   `json:"jwks_uri"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func fetchJSON(url string, target any) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

func postForm(url string, data url.Values) (map[string]any, error) {
	resp, err := http.PostForm(url, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func validateIDToken(idToken, expectedNonce string, jwks *jwksResponse) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode header & payload
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])

	var header map[string]any
	var payload map[string]any
	json.Unmarshal(headerJSON, &header)
	json.Unmarshal(payloadJSON, &payload)

	now := time.Now().Unix()
	errors := []string{}

	if payload["iss"] != issuer {
		errors = append(errors, fmt.Sprintf("iss: %v !== %s", payload["iss"], issuer))
	}
	aud, _ := payload["aud"].([]any)
	found := false
	for _, a := range aud {
		if a == clientID {
			found = true
		}
	}
	if !found {
		errors = append(errors, fmt.Sprintf("aud must contain %s", clientID))
	}
	if exp, ok := payload["exp"].(float64); ok && int64(exp) < now {
		errors = append(errors, "token expired")
	}
	if iat, ok := payload["iat"].(float64); ok && int64(iat) > now+60 {
		errors = append(errors, "iat in future")
	}
	if expectedNonce != "" && payload["nonce"] != expectedNonce {
		errors = append(errors, "nonce mismatch")
	}

	if len(errors) > 0 {
		for _, e := range errors {
			fmt.Printf("  FAIL: %s\n", e)
		}
		return nil, fmt.Errorf("ID Token validation failed")
	}

	// Verify signature using JWKS
	for _, key := range jwks.Keys {
		if key.Kid == header["kid"] {
			nBytes, _ := base64.RawURLEncoding.DecodeString(key.N)
			eBytes, _ := base64.RawURLEncoding.DecodeString(key.E)
			eInt := int(eBytes[0])<<16 | int(eBytes[1])<<8 | int(eBytes[2])
			nInt := new(big.Int).SetBytes(nBytes)

			pub := &rsa.PublicKey{N: nInt, E: eInt}
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sig); err != nil {
				return nil, fmt.Errorf("signature verification failed")
			}
			break
		}
	}

	fmt.Println("  ✅ ID Token validated")
	return payload, nil
}

func main() {
	fmt.Println("=== OIDC Discovery ===")
	var disc discovery
	fetchJSON(issuer+"/.well-known/openid-configuration", &disc)
	fmt.Printf("  issuer: %s\n  jwks_uri: %s\n", disc.Issuer, disc.JWKSUri)

	nonce := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	state := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", os.Getpid())))

	client := &http.Client{CheckRedirect: func(r *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	fmt.Println("\n1. Consent...")
	consentForm := url.Values{
		"response_type": {"code"}, "client_id": {clientID},
		"redirect_uri": {redirectURI}, "scope": {"openid profile email"},
		"state": {state}, "nonce": {nonce},
		"username": {"alice"}, "password": {getEnv("ALICE_PASSWORD", "password-alice")},
		"approve": {"yes"},
	}
	resp, _ := client.PostForm(issuer+"/consent", consentForm)
	location := resp.Header.Get("Location")
	resp.Body.Close()

	if location == "" {
		fmt.Println("  No redirect — consent failed")
		return
	}

	code, _ := url.Parse(location)
	authCode := code.Query().Get("code")
	fmt.Printf("2. Auth code: %s...\n", authCode[:20])

	fmt.Println("\n3. Exchange code for tokens...")
	tokens, _ := postForm(issuer+"/token", url.Values{
		"grant_type": {"authorization_code"}, "code": {authCode},
		"client_id": {clientID}, "client_secret": {clientSecret},
		"redirect_uri": {redirectURI},
	})
	for k, v := range tokens {
		s, _ := v.(string)
		display := v
		if len(s) > 50 {
			display = s[:50] + "..."
		}
		fmt.Printf("  %s: %v\n", k, display)
	}

	idToken, _ := tokens["id_token"].(string)

	fmt.Println("\n4. Validate ID Token...")
	var jwks jwksResponse
	fetchJSON(issuer+"/.well-known/jwks.json", &jwks)
	claims, err := validateIDToken(idToken, nonce, &jwks)
	if err != nil {
		fmt.Printf("  FAIL: %v\n", err)
		return
	}
	fmt.Printf("  sub: %v\n  name: %v\n  email: %v\n", claims["sub"], claims["name"], claims["email"])

	fmt.Println("\n5. Fetch UserInfo...")
	accessToken, _ := tokens["access_token"].(string)
	req, _ := http.NewRequest("GET", issuer+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, _ = http.DefaultClient.Do(req)
	var ui map[string]any
	json.NewDecoder(resp.Body).Decode(&ui)
	fmt.Printf("  %d: %v\n", resp.StatusCode, ui)
	resp.Body.Close()

	_ = x509.MarshalPKIXPublicKey
	_ = pem.EncodeToMemory
}
