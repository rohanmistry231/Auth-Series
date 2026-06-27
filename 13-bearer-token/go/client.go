package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

var baseURL = getEnv("SERVER_URL", "http://127.0.0.1:8000")

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func postForm(path string, data url.Values) (map[string]any, error) {
	resp, err := http.PostForm(baseURL+path, data)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)
	return result, nil
}

func get(path string, headers map[string]string) (map[string]any, error) {
	req, _ := http.NewRequest("GET", baseURL+path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)
	return result, nil
}

func main() {
	fmt.Println("=== Step 1: Login (alice) ===")
	login, _ := postForm("/login", url.Values{"username": {"alice"}, "password": {getEnv("ALICE_PASSWORD", "password-alice")}})
	token := login["access_token"].(string)
	fmt.Printf("  Token: %s...\n", token[:32])
	fmt.Printf("  Scopes: %v\n", login["scope"])

	fmt.Println("\n=== Step 2: Access Protected (query param) ===")
	prot, _ := get(fmt.Sprintf("/protected?token=%s", token), nil)
	fmt.Printf("  %v\n", prot["message"])

	fmt.Println("\n=== Step 3: Access Protected (header) ===")
	prot2, _ := get("/protected", map[string]string{"Authorization": fmt.Sprintf("Bearer %s", token)})
	fmt.Printf("  %v\n", prot2["message"])

	fmt.Println("\n=== Step 4: Introspect ===")
	intro, _ := postForm("/introspect", url.Values{"token": {token}})
	fmt.Printf("  Active: %v  Sub: %v\n", intro["active"], intro["sub"])

	fmt.Println("\n=== Step 5: Revoke ===")
	rev, _ := postForm("/revoke", url.Values{"token": {token}})
	fmt.Printf("  Result: %v\n", rev["result"])

	fmt.Println("\n=== Step 6: Try revoked ===")
	prot3, _ := get(fmt.Sprintf("/protected?token=%s", token), nil)
	fmt.Printf("  Error: %v ✅\n", prot3["error"])

	fmt.Println("\n=== Step 7: Missing header ===")
	prot4, _ := get("/protected", nil)
	fmt.Printf("  Error: %v ✅\n", prot4["error"])
}
