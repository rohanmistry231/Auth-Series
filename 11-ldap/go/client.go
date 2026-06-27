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

func main() {
	fmt.Println("=== Login: newton / newton ===")
	login, _ := postForm("/login", url.Values{"username": {"newton"}, "password": {"newton"}})
	if err, has := login["error"]; has {
		fmt.Printf("  ❌ %v\n", err)
	} else {
		fmt.Printf("  ✅ Logged in as %v\n", login["username"])
		fmt.Printf("  DN: %v\n", login["dn"])
		attrs, _ := login["attributes"].(map[string]any)
		fmt.Printf("  cn: %v\n", attrs["cn"])
		fmt.Printf("  mail: %v\n", attrs["mail"])
	}

	fmt.Println("\n=== Login: wrong password ===")
	bad, _ := postForm("/login", url.Values{"username": {"newton"}, "password": {"wrong"}})
	fmt.Printf("  %v\n", bad["error"])

	fmt.Println("\n=== Search: all persons ===")
	search, _ := postForm("/search", url.Values{"filter": {"(objectClass=person)"}})
	if entries, has := search["entries"]; has {
		ents := entries.([]any)
		fmt.Printf("  Found %d entries:\n", len(ents))
		for i, e := range ents {
			if i >= 5 {
				break
			}
			entry := e.(map[string]any)
			fmt.Printf("    - %v\n", entry["dn"])
		}
		if len(ents) > 5 {
			fmt.Printf("    ... and %d more\n", len(ents)-5)
		}
	}
}
