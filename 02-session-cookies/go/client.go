package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
)

var (
	baseURL  = getEnv("SERVER_URL", "http://127.0.0.1:8000")
	username = getEnv("AUTH_USERNAME", "alice")
	password = getEnv("AUTH_PASSWORD", "password-alice")
)

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

func request(client *http.Client, method, path string, body any) (*response, error) {
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

	resp, err := client.Do(req)
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

func main() {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	fmt.Println("=== Public endpoint ===")
	resp, _ := request(client, http.MethodGet, "/public", nil)
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== Login ===")
	resp, _ = request(client, http.MethodPost, "/login", map[string]string{
		"username": username,
		"password": password,
	})
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== Protected endpoint (/me) ===")
	resp, _ = request(client, http.MethodGet, "/me", nil)
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== Create data (with CSRF) ===")
	csrfResp, _ := request(client, http.MethodGet, "/csrf-token", nil)
	token := csrfResp.Body["csrf_token"].(string)

	resp, _ = request(client, http.MethodPost, "/data", map[string]any{
		"csrf_token": token,
		"payload":    "hello",
	})
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== Create data (no CSRF — should fail) ===")
	resp, _ = request(client, http.MethodPost, "/data", map[string]any{
		"payload": "hello",
	})
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== Logout ===")
	resp, _ = request(client, http.MethodPost, "/logout", nil)
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== After logout (/me — should fail) ===")
	resp, _ = request(client, http.MethodGet, "/me", nil)
	fmt.Println(resp.Status, resp.Body)
}
