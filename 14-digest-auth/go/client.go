package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

var baseURL = getEnv("SERVER_URL", "http://127.0.0.1:8000")
var realm = "Auth Series"

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func computeResponse(username, password, method, uri, nonce, cnonce, nc, qop string) string {
	ha1 := md5Hex(fmt.Sprintf("%s:%s:%s", username, realm, password))
	ha2 := md5Hex(fmt.Sprintf("%s:%s", method, uri))
	return md5Hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2))
}

func main() {
	fmt.Println("=== Step 1: Request protected resource (no auth) ===")
	resp, _ := http.Get(baseURL + "/protected")
	fmt.Printf("  Status: %d\n", resp.StatusCode)
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	fmt.Printf("  WWW-Authenticate: %s...\n", wwwAuth[:min(len(wwwAuth), 60)])
	resp.Body.Close()

	parseParams := func(h string) map[string]string {
		params := make(map[string]string)
		for _, part := range strings.Split(h[7:], ",") {
			eqIdx := strings.Index(part, "=")
			if eqIdx < 0 {
				continue
			}
			k := strings.TrimSpace(part[:eqIdx])
			v := strings.TrimSpace(part[eqIdx+1:])
			v = strings.Trim(v, "\"")
			params[k] = v
		}
		return params
	}

	params := parseParams(wwwAuth)
	nonce := params["nonce"]
	opaque := params["opaque"]
	qop := params["qop"]
	fmt.Printf("  Nonce: %s...\n", nonce[:16])

	username := "alice"
	password := getEnv("ALICE_PASSWORD", "password-alice")
	b := make([]byte, 16)
	rand.Read(b)
	cnonce := md5Hex(hex.EncodeToString(b))[:16]
	nc := "00000001"
	uri := "/protected"
	response := computeResponse(username, password, "GET", uri, nonce, cnonce, nc, qop)

	fmt.Println("\n=== Step 2: Retry with Digest auth ===")
	digestHeader := fmt.Sprintf(`Digest username="%s",realm="%s",nonce="%s",uri="%s",qop=%s,nc=%s,cnonce="%s",response="%s",opaque="%s"`,
		username, realm, nonce, uri, qop, nc, cnonce, response, opaque)

	req, _ := http.NewRequest("GET", baseURL+"/protected", nil)
	req.Header.Set("Authorization", digestHeader)
	resp2, _ := http.DefaultClient.Do(req)
	fmt.Printf("  Status: %d\n", resp2.StatusCode)
	if resp2.StatusCode == 200 {
		body, _ := io.ReadAll(resp2.Body)
		var data map[string]any
		json.Unmarshal(body, &data)
		fmt.Printf("  ✅ %v\n", data["message"])
	}
	resp2.Body.Close()

	fmt.Println("\n=== Step 3: Replay nonce (should fail) ===")
	req2, _ := http.NewRequest("GET", baseURL+"/protected", nil)
	req2.Header.Set("Authorization", digestHeader)
	resp3, _ := http.DefaultClient.Do(req2)
	fmt.Printf("  Status: %d — %s\n", resp3.StatusCode, map[bool]string{true: "✅ Blocked", false: "❌"}[resp3.StatusCode == 401])
	resp3.Body.Close()
}
