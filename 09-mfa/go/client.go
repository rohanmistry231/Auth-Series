package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pquerna/otp/totp"
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

func main() {
	username := "alice"
	password := getEnv("ALICE_PASSWORD", "password-alice")

	fmt.Println("=== Step 1: Setup MFA ===")
	setup, _ := postForm("/setup", url.Values{"username": {username}, "password": {password}})
	fmt.Printf("  Secret: %v\n", setup["secret"])
	fmt.Printf("  QR URI: %v\n", setup["qr_uri"])

	fmt.Println("\n=== Step 2: Verify TOTP ===")
	secret, _ := setup["secret"].(string)
	currentCode, _ := totp.GenerateCode(secret, time.Now())
	fmt.Printf("  Current TOTP: %s\n", currentCode)
	verify, _ := postForm("/mfa/verify", url.Values{"username": {username}, "totp": {currentCode}})
	fmt.Printf("  %v\n", verify["message"])
	fmt.Printf("  Backup codes: %v\n", verify["backup_codes"])

	fmt.Println("\n=== Step 3: Login with MFA ===")
	code, _ := totp.GenerateCode(secret, time.Now())
	login, _ := postForm("/login", url.Values{"username": {username}, "password": {password}, "totp": {code}})
	fmt.Printf("  %v\n", login["message"])
	tok, _ := login["access_token"].(string)
	if len(tok) > 20 {
		tok = tok[:20] + "..."
	}
	fmt.Printf("  Token: %s\n", tok)

	fmt.Println("\n=== Step 4: Login with wrong TOTP ===")
	bad, _ := postForm("/login", url.Values{"username": {username}, "password": {password}, "totp": {"000000"}})
	fmt.Printf("  Status: %v\n", bad["error"])

	fmt.Println("\n=== Step 5: Recovery login ===")
	bcs, _ := verify["backup_codes"].([]any)
	if len(bcs) > 0 {
		bc, _ := bcs[0].(string)
		recovery, _ := postForm("/recovery", url.Values{"username": {username}, "backup_code": {bc}})
		fmt.Printf("  %v\n", recovery["message"])
		fmt.Printf("  Codes remaining: %v\n", recovery["codes_remaining"])
	}
}
