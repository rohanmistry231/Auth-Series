package main

import (
	"encoding/json"
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

func postForm(path string, data url.Values) (map[string]any, string, error) {
	reqBody := data.Encode()
	req, _ := http.NewRequest("POST", baseURL+path, strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, "", err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)
	return result, resp.Header.Get("Set-Cookie"), nil
}

func get(path string, headers map[string]string) (map[string]any, error) {
	req, _ := http.NewRequest("GET", baseURL+path, nil)
	for k, v := range headers { req.Header.Set(k, v) }
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	json.Unmarshal(body, &result)
	return result, nil
}

func main() {
	fmt.Println("=== BFF Pattern ===")
	login, cookie, _ := postForm("/bff/login", url.Values{"username": {"alice"}, "password": {alicePass}})
	fmt.Printf("  %v\n", login["message"])
	sid := ""
	if strings.Contains(cookie, "session_id=") {
		parts := strings.Split(cookie, "session_id=")
		sid = strings.Split(parts[1], ";")[0]
	}
	api, _ := get("/bff/api/data", map[string]string{"Cookie": fmt.Sprintf("session_id=%s", sid)})
	fmt.Printf("  %v\n", api["message"])

	fmt.Println("\n=== Token Rotation ===")
	issue, _, _ := postForm("/token/issue", url.Values{"username": {"alice"}, "password": {alicePass}})
	rt, _ := issue["refresh_token"].(string)
	fmt.Printf("  Issued: %s...\n", rt[:16])
	refresh1, _, _ := postForm("/token/refresh", url.Values{"refresh_token": {rt}})
	fmt.Printf("  Rotated: %v\n", refresh1["access_token"] != nil)
	refresh2, _, _ := postForm("/token/refresh", url.Values{"refresh_token": {rt}})
	fmt.Printf("  Replay: %v\n", refresh2["error"])

	fmt.Println("\n=== Gateway Auth ===")
	gTok, _, _ := postForm("/gateway/token", url.Values{"username": {"alice"}, "password": {alicePass}})
	tok, _ := gTok["access_token"].(string)
	gRes, _ := get("/gateway/api/resource", map[string]string{"Authorization": fmt.Sprintf("Bearer %s", tok)})
	fmt.Printf("  %v\n", gRes["message"])
}
