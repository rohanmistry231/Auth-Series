package main

import (
	"encoding/base64"
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

func get(url, user, pass string) (*response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	if user != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		return nil, err
	}

	return &response{Status: resp.StatusCode, Body: body}, nil
}

func main() {
	fmt.Println("=== Public endpoint ===")
	resp, _ := get(baseURL+"/public", "", "")
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== Protected endpoint (with auth) ===")
	resp, _ = get(baseURL+"/protected", username, password)
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== Protected endpoint (wrong password) ===")
	resp, _ = get(baseURL+"/protected", username, "wrong-password")
	fmt.Println(resp.Status, resp.Body)

	fmt.Println("\n=== Protected endpoint (no auth) ===")
	resp, _ = get(baseURL+"/protected", "", "")
	fmt.Println(resp.Status, resp.Body)
}
