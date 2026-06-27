package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
)

var baseURL = getEnv("SERVER_URL", "http://127.0.0.1:8000")

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func main() {
	fmt.Println("=== Step 1: Visit home page ===")
	resp, _ := http.Get(baseURL + "/")
	fmt.Printf("  Status: %d ✅\n", resp.StatusCode)
	resp.Body.Close()

	fmt.Println("\n=== Step 2: Click 'Sign in with Google' ===")
	httpClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, _ = httpClient.Get(baseURL + "/auth/google/login")
	loc1 := resp.Header.Get("Location")
	fmt.Printf("  Redirected to: %s...\n", loc1[:min(len(loc1), 80)])
	resp.Body.Close()

	fmt.Println("\n=== Step 3: Follow redirect to mock provider ===")
	resp, _ = http.Get(baseURL + loc1)
	fmt.Printf("  Status: %d ✅\n", resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	fmt.Println("\n=== Step 4: Allow access ===")
	re := regexp.MustCompile(`action="([^"]+)"`)
	match := re.FindStringSubmatch(string(body))
	actionPath := "/mock/google/consent"
	if len(match) > 1 {
		actionPath = match[1]
	}
	resp, _ = httpClient.PostForm(baseURL+actionPath, url.Values{
		"client_id":    {"google-client-id"},
		"redirect_uri": {"http://127.0.0.1:8000/auth/google/callback"},
		"action":       {"allow"},
	})
	loc2 := resp.Header.Get("Location")
	fmt.Printf("  Redirected to: %s...\n", loc2[:min(len(loc2), 80)])
	resp.Body.Close()

	fmt.Println("\n=== Step 5: Follow callback to app ===")
	resp, _ = httpClient.Get(baseURL + loc2)
	loc3 := resp.Header.Get("Location")
	fmt.Printf("  Redirected to: %s\n", loc3)
	resp.Body.Close()

	resp, _ = http.Get(baseURL + loc3)
	fmt.Printf("  Status: %d\n", resp.StatusCode)
	if resp.StatusCode == 200 {
		fmt.Println("  ✅ Successfully signed in with Google!")
	}
	resp.Body.Close()
}
