package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

var (
	baseURL  = getEnv("SERVER_URL", "http://127.0.0.1:8000")
	username = getEnv("AUTH_USERNAME", "alice")
	password = getEnv("AUTH_PASSWORD", "password-alice")
)

var tokens = struct {
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
}{}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type response struct {
	Status int
	Body   map[string]any
}

func request(method, path string, body any, bearer string) (*response, error) {
	url := baseURL + path

	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}

	return &response{Status: resp.StatusCode, Body: result}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func main() {
	fmt.Println("=== 1. Login ===")
	resp, _ := request(http.MethodPost, "/login", map[string]string{
		"username": username,
		"password": password,
	}, "")
	tokens.Access, _ = resp.Body["access_token"].(string)
	tokens.Refresh, _ = resp.Body["refresh_token"].(string)
	fmt.Println(resp.Status, map[string]string{
		"access_token":  truncate(tokens.Access, 30),
		"refresh_token": truncate(tokens.Refresh, 30),
	})

	fmt.Println("\n=== 2. Access protected endpoint ===")
	resp, _ = request(http.MethodGet, "/protected", nil, tokens.Access)
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== 3. JWKS endpoint ===")
	resp, _ = request(http.MethodGet, "/.well-known/jwks.json", nil, "")
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== 4. Refresh tokens ===")
	resp, _ = request(http.MethodPost, "/refresh", map[string]string{
		"refresh_token": tokens.Refresh,
	}, "")
	tokens.Access, _ = resp.Body["access_token"].(string)
	tokens.Refresh, _ = resp.Body["refresh_token"].(string)
	fmt.Println(resp.Status, map[string]string{
		"access_token":  truncate(tokens.Access, 30),
		"refresh_token": truncate(tokens.Refresh, 30),
	})

	fmt.Println("\n=== 5. Protected with new access token ===")
	resp, _ = request(http.MethodGet, "/protected", nil, tokens.Access)
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== 6. Try revoked refresh token ===")
	resp, _ = request(http.MethodPost, "/refresh", map[string]string{
		"refresh_token": "some-revoked-token",
	}, "")
	fmt.Println(resp.Status, resp.Body)
}
