package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
)

var baseURL = getEnv("SERVER_URL", "http://127.0.0.1:8000")

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

type response struct {
	Status int
	Body   map[string]any
}

func request(method, path string, body any, apiKey string) (*response, error) {
	url := baseURL + path

	var reqBody io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewReader(data)
	}

	req, _ := http.NewRequest(method, url, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(raw, &result)

	return &response{Status: resp.StatusCode, Body: result}, nil
}

func main() {
	fmt.Println("=== Create API key ===")
	created, _ := request("POST", "/keys", map[string]any{
		"name": "My App Key", "scopes": []string{"read", "write"}, "expires_in_days": 30,
	}, "")
	apiKey, _ := created.Body["key"].(string)
	fmt.Printf("  Created: %v...%v\n", created.Body["prefix"], created.Body["key_suffix"])

	fmt.Println("\n=== Public endpoint ===")
	pub, _ := request("GET", "/api/public", nil, "")
	fmt.Printf("  %d: %v\n", pub.Status, pub.Body)

	fmt.Println("\n=== Protected (valid key) ===")
	prot, _ := request("GET", "/api/data", nil, apiKey)
	fmt.Printf("  %d: %v\n", prot.Status, prot.Body)

	fmt.Println("\n=== Protected (invalid key) ===")
	bad, _ := request("GET", "/api/data", nil, "user_stripe_key_invalid")
	fmt.Printf("  %d: %v\n", bad.Status, bad.Body)

	fmt.Println("\n=== Admin (no admin scope) ===")
	admin, _ := request("GET", "/api/admin", nil, apiKey)
	fmt.Printf("  %d: %v\n", admin.Status, admin.Body)

	fmt.Println("\n=== Create admin key ===")
	adminKeyResp, _ := request("POST", "/keys", map[string]any{
		"name": "Admin Key", "scopes": []string{"read", "write", "admin"},
	}, "")
	adminKey, _ := adminKeyResp.Body["key"].(string)

	fmt.Println("\n=== Admin (with admin scope) ===")
	adminOk, _ := request("GET", "/api/admin", nil, adminKey)
	fmt.Printf("  %d: %v\n", adminOk.Status, adminOk.Body)

	fmt.Println("\n=== Rotate key ===")
	keyID, _ := created.Body["id"].(string)
	rot, _ := request("POST", "/keys/"+keyID+"/rotate", nil, "")
	fmt.Printf("  %d: %v\n", rot.Status, rot.Body["message"])

	fmt.Println("\n=== Old key fails ===")
	old, _ := request("GET", "/api/data", nil, apiKey)
	fmt.Printf("  %d: %v\n", old.Status, old.Body)
}
