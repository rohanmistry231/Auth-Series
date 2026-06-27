package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

const realm = "Auth Series"

var users = map[string]string{
	"alice": getEnv("ALICE_PASSWORD", "password-alice"),
	"bob":   getEnv("BOB_PASSWORD", "password-bob"),
}

var usedNonces = make(map[string]bool)

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

func computeHa1(username, password string) string {
	return md5Hex(fmt.Sprintf("%s:%s:%s", username, realm, password))
}

func computeHa2(method, uri string) string {
	return md5Hex(fmt.Sprintf("%s:%s", method, uri))
}

func computeResponse(ha1, nonce, nc, cnonce, qop, ha2 string) string {
	return md5Hex(fmt.Sprintf("%s:%s:%s:%s:%s:%s", ha1, nonce, nc, cnonce, qop, ha2))
}

func parseDigestHeader(header string) map[string]string {
	params := make(map[string]string)
	if !strings.HasPrefix(header, "Digest ") {
		return params
	}
	for _, part := range strings.Split(header[7:], ",") {
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

func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, s string, status int) {
	w.Header().Set("Content-Type", "text/html;charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(s))
}

func unauthorized(w http.ResponseWriter) {
	nonce := generateNonce()
	opaque := generateNonce()
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Digest realm="%s",nonce="%s",opaque="%s",qop="auth",algorithm=MD5`, realm, nonce, opaque))
	http.Error(w, "Unauthorized", 401)
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			sendHTML(w, "Not found", 404)
			return
		}
		sendHTML(w, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>Digest Auth Demo</h2>
<p><a href="/protected">/protected</a></p></body></html>`, 200)
	})

	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		params := parseDigestHeader(r.Header.Get("Authorization"))
		if params["username"] == "" {
			unauthorized(w)
			return
		}

		username := params["username"]
		password, ok := users[username]
		if !ok {
			unauthorized(w)
			return
		}

		nonce := params["nonce"]
		if usedNonces[nonce] {
			unauthorized(w)
			return
		}

		uri := params["uri"]
		if uri == "" {
			uri = r.URL.Path
		}
		qop := params["qop"]
		if qop == "" {
			qop = "auth"
		}
		nc := params["nc"]
		if nc == "" {
			nc = "00000001"
		}
		cnonce := params["cnonce"]
		responseClient := params["response"]

		ha1 := computeHa1(username, password)
		ha2 := computeHa2(r.Method, uri)
		expected := computeResponse(ha1, nonce, nc, cnonce, qop, ha2)

		if subtle.ConstantTimeCompare([]byte(expected), []byte(responseClient)) != 1 {
			unauthorized(w)
			return
		}

		usedNonces[nonce] = true
		sendJSON(w, 200, map[string]any{
			"message": fmt.Sprintf("Authenticated as %s", username),
			"scheme":  "Digest",
			"realm":   realm,
		})
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("Digest Auth Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
