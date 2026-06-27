package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	authServer = getEnv("AUTH_SERVER", "http://localhost:8000")
	username   = "alice"
	password   = getEnv("ALICE_PASSWORD", "password-alice")
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func b64url(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func request(method, path string, form url.Values, headers map[string]string) (*http.Response, error) {
	u := authServer + path
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client.Do(req)
}

func readBody(resp *http.Response) (map[string]any, error) {
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func displayTokens(body map[string]any) {
	for k, v := range body {
		s, ok := v.(string)
		display := v
		if ok && len(s) > 40 {
			display = s[:40] + "..."
		}
		fmt.Printf("   %s: %v\n", k, display)
	}
}

func authCodeFlow() map[string]any {
	fmt.Println("=== Authorization Code Flow ===")
	redirectURI := "http://localhost:8001/callback"
	state := b64url([]byte(fmt.Sprintf("%d", os.Getpid())))

	resp, _ := request(http.MethodGet, "/authorize", nil, nil)
	resp.Body.Close()

	form := url.Values{
		"response_type": {"code"}, "client_id": {"webapp"},
		"redirect_uri": {redirectURI}, "scope": {"openid profile"},
		"state": {state}, "username": {username}, "password": {password},
		"approve": {"yes"},
	}
	resp, _ = request(http.MethodPost, "/consent", form, nil)
	resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		fmt.Println("   No redirect (consent may have failed)")
		return nil
	}

	parsed, _ := url.Parse(location)
	code := parsed.Query().Get("code")
	fmt.Printf("   Auth code: %s...\n", code[:20])

	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"webapp"},
		"client_secret": {getEnv("WEBAPP_SECRET", "webapp-secret")},
		"redirect_uri": {redirectURI},
	}
	resp, _ = request(http.MethodPost, "/token", tokenForm, nil)
	body, _ := readBody(resp)
	fmt.Printf("   Token: %d\n", resp.Status)
	displayTokens(body)
	resp.Body.Close()
	return body
}

func pkceFlow() {
	fmt.Println("\n=== Authorization Code + PKCE Flow ===")
	redirectURI := "http://localhost:3000/callback"
	state := b64url([]byte("pkce-state"))

	verifier := make([]byte, 32)
	rand.Read(verifier)
	codeVerifier := b64url(verifier)
	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := b64url(h[:])

	resp, _ := request(http.MethodGet, "/authorize", nil, nil)
	resp.Body.Close()

	form := url.Values{
		"response_type": {"code"}, "client_id": {"spa"},
		"redirect_uri": {redirectURI}, "scope": {"openid profile"},
		"state": {state}, "username": {username}, "password": {password},
		"approve": {"yes"}, "code_challenge": {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	resp, _ = request(http.MethodPost, "/consent", form, nil)
	resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		fmt.Println("   No redirect")
		return
	}

	parsed, _ := url.Parse(location)
	code := parsed.Query().Get("code")
	fmt.Printf("   Auth code: %s...\n", code[:20])

	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"spa"}, "redirect_uri": {redirectURI},
		"code_verifier": {codeVerifier},
	}
	resp, _ = request(http.MethodPost, "/token", tokenForm, nil)
	body, _ := readBody(resp)
	fmt.Printf("   Token: %d\n", resp.Status)
	displayTokens(body)
	resp.Body.Close()
}

func clientCredsFlow() {
	fmt.Println("\n=== Client Credentials Flow ===")
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"service-a"},
		"client_secret": {getEnv("SERVICE_A_SECRET", "service-a-secret")},
		"scope": {"read:data"},
	}
	resp, _ := request(http.MethodPost, "/token", form, nil)
	body, _ := readBody(resp)
	fmt.Printf("   Token: %d\n", resp.Status)
	displayTokens(body)
	resp.Body.Close()

	userinfoResp, _ := request(http.MethodGet, "/userinfo", nil, map[string]string{
		"Authorization": "Bearer " + body["access_token"].(string),
	})
	userBody, _ := readBody(userinfoResp)
	fmt.Printf("   /userinfo: %d %v\n", userinfoResp.Status, userBody)
	userinfoResp.Body.Close()
}

func deviceFlow() {
	fmt.Println("\n=== Device Code Flow ===")
	form := url.Values{"client_id": {"webapp"}, "scope": {"openid profile"}}
	resp, _ := request(http.MethodPost, "/device/code", form, nil)
	body, _ := readBody(resp)
	fmt.Printf("1. Device code: %v\n", body)
	resp.Body.Close()

	userCode, _ := body["user_code"].(string)
	deviceCode, _ := body["device_code"].(string)
	fmt.Printf("   User code: %s\n", userCode)

	approveForm := url.Values{
		"user_code": {userCode}, "username": {username},
		"password": {password},
	}
	resp, _ = request(http.MethodPost, "/device/approve", approveForm, nil)
	approveBody, _ := readBody(resp)
	fmt.Printf("2. Approval: %d %v\n", resp.Status, approveBody)
	resp.Body.Close()

	tokenForm := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode}, "client_id": {"webapp"},
	}
	resp, _ = request(http.MethodPost, "/token", tokenForm, nil)
	tokenBody, _ := readBody(resp)
	fmt.Printf("3. Token: %d\n", resp.Status)
	displayTokens(tokenBody)
	resp.Body.Close()
}

func refreshFlow(tokens map[string]any) {
	fmt.Println("\n=== Token Refresh Flow ===")
	refreshToken, ok := tokens["refresh_token"].(string)
	if !ok {
		fmt.Println("No refresh token")
		return
	}

	form := url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refreshToken},
		"client_id": {"webapp"},
		"client_secret": {getEnv("WEBAPP_SECRET", "webapp-secret")},
	}
	resp, _ := request(http.MethodPost, "/token", form, nil)
	body, _ := readBody(resp)
	fmt.Printf("   Refresh: %d\n", resp.Status)
	displayTokens(body)
	resp.Body.Close()
}

func main() {
	flow := "all"
	if len(os.Args) > 1 {
		flow = os.Args[1]
	}

	switch flow {
	case "all":
		tokens := authCodeFlow()
		if tokens != nil {
			refreshFlow(tokens)
		}
		pkceFlow()
		clientCredsFlow()
		deviceFlow()
	case "auth-code":
		tokens := authCodeFlow()
		if tokens != nil {
			refreshFlow(tokens)
		}
	case "pkce":
		pkceFlow()
	case "client-creds":
		clientCredsFlow()
	case "device":
		deviceFlow()
	default:
		fmt.Println("Usage: go run client.go [auth-code|pkce|client-creds|device|all]")
	}
}
