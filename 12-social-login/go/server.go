package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var providerSecret = getEnv("PROVIDER_CLIENT_SECRET", "provider-secret")

var providers = map[string]map[string]any{
	"google": {
		"name":             "Google",
		"client_id":        "google-client-id",
		"client_secret":    providerSecret,
		"authorize_path":   "/mock/google/authorize",
		"token_path":       "/mock/google/token",
		"userinfo_path":    "/mock/google/userinfo",
		"scopes":           []string{"openid", "profile", "email"},
	},
	"github": {
		"name":             "GitHub",
		"client_id":        "github-client-id",
		"client_secret":    providerSecret,
		"authorize_path":   "/mock/github/authorize",
		"token_path":       "/mock/github/token",
		"userinfo_path":    "/mock/github/userinfo",
		"scopes":           []string{"read:user", "user:email"},
	},
}

var mockUsers = map[string]map[string]any{
	"google": {
		"sub":            "google-12345",
		"name":           "Alice Google",
		"email":          "alice@gmail.com",
		"email_verified": true,
		"picture":        "https://example.com/avatars/alice-google.png",
	},
	"github": {
		"sub":            "github-67890",
		"name":           "GitHub Alice",
		"email":          "alice@github.com",
		"email_verified": true,
		"picture":        "https://example.com/avatars/alice-github.png",
		"login":          "alice-dev",
	},
}

var (
	authCodes = make(map[string]map[string]any)
	sessions  = make(map[string]map[string]any)
)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hmacSign(payload string) string {
	mac := hmac.New(sha256.New, []byte(providerSecret))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func makeIDToken(provider string, user map[string]any) string {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadMap := map[string]any{
		"iss": fmt.Sprintf("https://%s.com", provider),
		"sub": user["sub"],
		"aud": providers[provider]["client_id"],
		"exp": time.Now().Unix() + 3600,
		"iat": time.Now().Unix(),
	}
	for k, v := range user {
		payloadMap[k] = v
	}
	payloadJSON, _ := json.Marshal(payloadMap)
	payload := base64URLEncode(payloadJSON)
	sig := hmacSign(fmt.Sprintf("%s.%s", header, payload))
	return fmt.Sprintf("%s.%s.%s", header, payload, sig)
}

func verifyIDToken(provider string, token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	expectedSig := hmacSign(fmt.Sprintf("%s.%s", parts[0], parts[1]))
	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return nil, fmt.Errorf("invalid signature")
	}
	payloadBytes, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding")
	}
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)
	prov := providers[provider]
	if payload["aud"] != prov["client_id"] {
		return nil, fmt.Errorf("invalid audience")
	}
	return payload, nil
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, body string, status int) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(body))
}

func pageHTML(title, body string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">%s</body></html>`, body)
}

func redirect(w http.ResponseWriter, r *http.Request, url string) {
	http.Redirect(w, r, url, 302)
}

func parseForm(r *http.Request) {
	r.ParseForm()
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			sendHTML(w, "Not found", 404)
			return
		}
		sendHTML(w, pageHTML("Social Login Demo", `
<h2>Social Login Demo</h2>
<p style="color:#666">Built-in mock provider — no real credentials needed.</p>
<p><a href="/auth/google/login" style="display:inline-block;padding:12px 24px;background:#4285f4;color:#fff;text-decoration:none;border-radius:4px;margin:8px 0">Sign in with Google</a></p>
<p><a href="/auth/github/login" style="display:inline-block;padding:12px 24px;background:#24292f;color:#fff;text-decoration:none;border-radius:4px;margin:8px 0">Sign in with GitHub</a></p>
`), 200)
	})

	// App: Initiate login
	mux.HandleFunc("/auth/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 {
			sendHTML(w, "Not found", 404)
			return
		}
		provider := parts[1]
		action := parts[2]

		if action == "login" && r.Method == "GET" {
			prov, ok := providers[provider]
			if !ok {
				sendHTML(w, "Unknown provider", 404)
				return
			}
			redirectURI := fmt.Sprintf("http://127.0.0.1:8000/auth/%s/callback", provider)
			scopes := strings.Join(prov["scopes"].([]string), "+")
			params := fmt.Sprintf("response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
				prov["client_id"], url.QueryEscape(redirectURI), scopes, newUUID())
			redirect(w, r, fmt.Sprintf("%s?%s", prov["authorize_path"], params))
			return
		}

		if action == "callback" && r.Method == "GET" {
			prov, ok := providers[provider]
			if !ok {
				sendHTML(w, "Unknown provider", 404)
				return
			}
			code := r.URL.Query().Get("code")
			if code == "" {
				sendHTML(w, "Missing code", 400)
				return
			}

			tokenResp, err := http.PostForm(fmt.Sprintf("http://127.0.0.1:8000%s", prov["token_path"]), url.Values{
				"grant_type":   {"authorization_code"},
				"code":         {code},
				"redirect_uri": {fmt.Sprintf("http://127.0.0.1:8000/auth/%s/callback", provider)},
				"client_id":    {prov["client_id"].(string)},
				"client_secret": {prov["client_secret"].(string)},
			})
			if err != nil {
				sendJSON(w, 500, map[string]string{"error": "Token exchange failed"})
				return
			}
			defer tokenResp.Body.Close()
			tokenBody, _ := io.ReadAll(tokenResp.Body)
			var tokenData map[string]any
			json.Unmarshal(tokenBody, &tokenData)

			userInfo, err := verifyIDToken(provider, tokenData["id_token"].(string))
			if err != nil {
				sendJSON(w, 401, map[string]string{"error": err.Error()})
				return
			}

			userinfoResp, _ := http.Get(fmt.Sprintf("http://127.0.0.1:8000%s", prov["userinfo_path"]))
			defer userinfoResp.Body.Close()
			userinfoBody, _ := io.ReadAll(userinfoResp.Body)
			var userinfo map[string]any
			json.Unmarshal(userinfoBody, &userinfo)

			sessionID := newUUID()
			sessions[sessionID] = map[string]any{
				"provider":    provider,
				"provider_id": userInfo["sub"],
				"name":        userinfo["name"],
				"email":       userinfo["email"],
			}

			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    sessionID,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
				Path:     "/",
			})
			redirect(w, r, "/dashboard")
			return
		}

		sendHTML(w, "Not found", 404)
	})

	// App: Dashboard
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		sendHTML(w, pageHTML("Dashboard", `
<h2>Dashboard</h2>
<p>You are logged in!</p>
<p><a href="/">← Back</a></p>
`), 200)
	})

	// Mock Provider: Authorize
	mux.HandleFunc("/mock/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) < 3 {
			sendHTML(w, "Not found", 404)
			return
		}
		provider := parts[1]
		endpoint := parts[2]

		prov, ok := providers[provider]
		if !ok {
			sendHTML(w, "Unknown provider", 404)
			return
		}

		if endpoint == "authorize" && r.Method == "GET" {
			clientID := r.URL.Query().Get("client_id")
			redirectURI := r.URL.Query().Get("redirect_uri")
			if clientID != prov["client_id"] {
				sendHTML(w, "Invalid client_id", 400)
				return
			}

			sendHTML(w, pageHTML(fmt.Sprintf("%s Sign In", prov["name"]), fmt.Sprintf(`
<h2>%s — Sign In</h2>
<p style="color:#666">Mock %s consent page.</p>
<p>Signed in as: <strong>%s</strong></p>
<form method="post" action="/mock/%s/consent">
  <input type="hidden" name="client_id" value="%s">
  <input type="hidden" name="redirect_uri" value="%s">
  <p>
    <button type="submit" name="action" value="allow" style="padding:10px 24px;background:#34a853;color:#fff;border:none;border-radius:4px;cursor:pointer">Allow</button>
    <button type="submit" name="action" value="deny" style="padding:10px 24px;background:#ea4335;color:#fff;border:none;border-radius:4px;cursor:pointer">Deny</button>
  </p>
</form>`, prov["name"], prov["name"], mockUsers[provider]["name"], provider, clientID, redirectURI)), 200)
			return
		}

		if endpoint == "consent" && r.Method == "POST" {
			parseForm(r)
			clientID := r.FormValue("client_id")
			redirectURI := r.FormValue("redirect_uri")
			action := r.FormValue("action")

			if clientID != prov["client_id"] {
				sendHTML(w, "Invalid client_id", 400)
				return
			}

			if action != "allow" {
				redirect(w, r, fmt.Sprintf("%s?error=access_denied", redirectURI))
				return
			}

			code := newUUID()
			authCodes[code] = map[string]any{
				"provider":  provider,
				"client_id": clientID,
				"exp":       time.Now().Unix() + 300,
			}
			redirect(w, r, fmt.Sprintf("%s?code=%s", redirectURI, code))
			return
		}

		if endpoint == "token" && r.Method == "POST" {
			parseForm(r)
			code := r.FormValue("code")
			clientSecret := r.FormValue("client_secret")

			if clientSecret != prov["client_secret"] {
				sendJSON(w, 401, map[string]string{"error": "Invalid client_secret"})
				return
			}

			auth, ok := authCodes[code]
			if !ok {
				sendJSON(w, 401, map[string]string{"error": "Invalid code"})
				return
			}
			if auth["exp"].(int64) < time.Now().Unix() {
				sendJSON(w, 401, map[string]string{"error": "Code expired"})
				return
			}

			sendJSON(w, 200, map[string]any{
				"access_token": newUUID(),
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     makeIDToken(provider, mockUsers[provider]),
			})
			return
		}

		if endpoint == "userinfo" && r.Method == "GET" {
			sendJSON(w, 200, mockUsers[provider])
			return
		}

		sendHTML(w, "Not found", 404)
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Social Login Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
