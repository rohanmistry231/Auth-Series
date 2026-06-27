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
var alicePass = getEnv("ALICE_PASSWORD", "password-alice")

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" { return v }
	return f
}

func main() {
	fmt.Println("=== Check Security Headers ===")
	resp, _ := http.Get(baseURL + "/")
	for _, h := range []string{"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"} {
		val := resp.Header.Get(h)
		if val != "" { fmt.Printf("  %s: %s\n", h, val) } else { fmt.Printf("  %s: ❌ MISSING\n", h) }
	}
	resp.Body.Close()

	fmt.Println("\n=== Login (success) ===")
	resp, _ = http.PostForm(baseURL+"/login", url.Values{"username": {"alice"}, "password": {alicePass}})
	fmt.Printf("  Status: %d %s\n", resp.StatusCode, map[bool]string{true: "✅", false: "❌"}[resp.StatusCode == 200])
	resp.Body.Close()

	fmt.Println("\n=== Rate limit test ===")
	for i := 0; i < 7; i++ {
		resp, _ = http.PostForm(baseURL+"/login", url.Values{"username": {"alice"}, "password": {"wrong"}})
		if resp.StatusCode == 429 {
			fmt.Printf("  ✅ Rate limited on attempt %d\n", i+1)
			resp.Body.Close()
			break
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 401 { fmt.Printf("  Attempt %d: %d\n", i+1, resp.StatusCode) }
		_ = body
	}

	fmt.Println("\n=== Audit Log ===")
	resp, _ = http.Get(baseURL + "/audit-log")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(body), "LOGIN") {
		fmt.Println("  ✅ Entries found")
	} else {
		fmt.Println("  No entries")
	}
}
