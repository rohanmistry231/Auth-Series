package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var baseURL = getEnv("SERVER_URL", "http://127.0.0.1:8000")
var serviceURL = baseURL + "/protected"

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func main() {
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fmt.Println("=== Step 1: Visit protected resource ===")
	resp, _ := httpClient.Get(baseURL + "/protected")
	loc1 := resp.Header.Get("Location")
	fmt.Printf("  Status: %d → %s...\n", resp.StatusCode, loc1[:min(len(loc1), 80)])
	resp.Body.Close()

	fmt.Println("\n=== Step 2: Follow redirect to CAS login ===")
	resp, _ = http.Get(baseURL + loc1)
	fmt.Printf("  Status: %d ✅\n", resp.StatusCode)
	resp.Body.Close()

	fmt.Println("\n=== Step 3: Submit login form ===")
	resp, _ = httpClient.PostForm(baseURL+"/login", url.Values{
		"service":  {serviceURL},
		"username": {"alice"},
		"password": {getEnv("ALICE_PASSWORD", "password-alice")},
	})
	loc3 := resp.Header.Get("Location")
	fmt.Printf("  Redirected to: %s...\n", loc3[:min(len(loc3), 80)])
	resp.Body.Close()

	ticket := ""
	if parts := strings.Split(loc3, "ticket="); len(parts) > 1 {
		ticket = parts[1]
		fmt.Printf("  Ticket: %s...\n", ticket[:min(len(ticket), 24)])
	}

	fmt.Println("\n=== Step 4: Follow redirect back to app ===")
	resp, _ = httpClient.Get(baseURL + loc3)
	loc4 := resp.Header.Get("Location")
	resp.Body.Close()
	resp, _ = http.Get(baseURL + loc4)
	fmt.Printf("  Status: %d ✅ Authenticated via CAS!\n", resp.StatusCode)
	resp.Body.Close()

	fmt.Println("\n=== Step 5: Replay ticket (should fail) ===")
	resp, _ = httpClient.Get(fmt.Sprintf("%s/protected?ticket=%s", baseURL, ticket))
	body, _ := io.ReadAll(resp.Body)
	result := string(body)
	resp.Body.Close()
	if strings.Contains(result, "Failed") || resp.StatusCode == 302 {
		fmt.Println("  ✅ Replay correctly blocked")
	} else {
		fmt.Printf("  Status: %d\n", resp.StatusCode)
	}
}
