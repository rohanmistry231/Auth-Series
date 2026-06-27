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

func main() {
	email := "alice@example.com"

	fmt.Println("=== Step 1: Request Magic Link ===")
	resp, _ := http.PostForm(baseURL+"/auth/request", url.Values{"email": {email}})
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var result map[string]any
	json.Unmarshal(body, &result)
	fmt.Printf("  %v\n", result["message"])
	fmt.Printf("  Expires in: %v\n", result["expires_in"])
	magicURL, _ := result["magic_url"].(string)
	fmt.Printf("  Magic URL: %s\n", magicURL)

	fmt.Println("\n=== Step 2: Verify Magic Link ===")
	resp2, _ := http.Get(magicURL)
	fmt.Printf("  Status: %d\n", resp2.StatusCode)
	if resp2.StatusCode == 200 {
		fmt.Println("  ✅ Successfully authenticated!")
	} else {
		b, _ := io.ReadAll(resp2.Body)
		fmt.Printf("  ❌ Failed: %s\n", string(b))
	}
	resp2.Body.Close()

	fmt.Println("\n=== Step 3: Replay token (should fail) ===")
	resp3, _ := http.Get(magicURL)
	fmt.Printf("  Status: %d\n", resp3.StatusCode)
	if resp3.StatusCode == 401 {
		fmt.Println("  ✅ Replay correctly blocked")
	}
	resp3.Body.Close()
}
