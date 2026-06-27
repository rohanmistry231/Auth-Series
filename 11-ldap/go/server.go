package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"gopkg.in/ldap.v3"
)

var (
	ldapHost       = getEnv("LDAP_HOST", "ldap.forumsys.com")
	ldapPort       = getIntEnv("LDAP_PORT", 389)
	ldapBaseDN     = getEnv("LDAP_BASE_DN", "dc=example,dc=com")
	ldapBindDN     = getEnv("LDAP_BIND_DN", "cn=read-only-admin,dc=example,dc=com")
	ldapBindPass   = getEnv("LDAP_BIND_PASSWORD", "password")
	ldapUserFilter = getEnv("LDAP_USER_FILTER", "(&(uid={username})(objectClass=person))")
)

var sessions = make(map[string]any)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func getIntEnv(k string, f int) int {
	if v := os.Getenv(k); v != "" {
		var i int
		if _, err := fmt.Sscanf(v, "%d", &i); err == nil {
			return i
		}
	}
	return f
}

func newUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func dialLDAP() (*ldap.Conn, error) {
	return ldap.Dial("tcp", fmt.Sprintf("%s:%d", ldapHost, ldapPort))
}

func sendJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func sendHTML(w http.ResponseWriter, s string, status int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(status)
	w.Write([]byte(s))
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
		sendHTML(w, `<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>LDAP Auth Demo</h2>
<p>Test users: <code>newton</code>, <code>galileo</code>, <code>einstein</code></p>
<form method="post" action="/login"><p><label>User: <input name="username" value="newton"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Login</button></p></form>
<form method="post" action="/search">
<p><label>Filter: <input name="filter" value="(objectClass=person)"></label></p>
<p><button type="submit">Search</button></p></form></body></html>`, 200)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		username := r.FormValue("username")
		password := r.FormValue("password")

		conn, err := dialLDAP()
		if err != nil {
			sendJSON(w, 500, map[string]string{"error": "LDAP connection failed"})
			return
		}
		defer conn.Close()

		err = conn.Bind(ldapBindDN, ldapBindPass)
		if err != nil {
			sendJSON(w, 500, map[string]string{"error": "LDAP service bind failed"})
			return
		}

		filter := strings.ReplaceAll(ldapUserFilter, "{username}", ldap.EscapeFilter(username))
		searchReq := ldap.NewSearchRequest(
			ldapBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			filter,
			[]string{"*"},
			nil,
		)

		sr, err := conn.Search(searchReq)
		if err != nil {
			sendJSON(w, 500, map[string]string{"error": "LDAP search failed"})
			return
		}

		if len(sr.Entries) == 0 {
			sendJSON(w, 401, map[string]string{"error": "User not found"})
			return
		}

		entry := sr.Entries[0]
		userDN := entry.DN

		err = conn.Bind(userDN, password)
		if err != nil {
			sendJSON(w, 401, map[string]string{"error": "Invalid password"})
			return
		}

		sessionID := newUUID()
		attrs := make(map[string]string)
		for _, attr := range entry.Attributes {
			attrs[attr.Name] = attr.Values[0]
		}
		sessions[sessionID] = map[string]any{"dn": userDN, "username": username}

		sendJSON(w, 200, map[string]any{
			"session_id": sessionID,
			"dn":         userDN,
			"username":   username,
			"attributes": attrs,
		})
	})

	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		parseForm(r)
		filter := r.FormValue("filter")

		conn, err := dialLDAP()
		if err != nil {
			sendJSON(w, 500, map[string]string{"error": "LDAP connection failed"})
			return
		}
		defer conn.Close()

		err = conn.Bind(ldapBindDN, ldapBindPass)
		if err != nil {
			sendJSON(w, 500, map[string]string{"error": "LDAP service bind failed"})
			return
		}

		searchReq := ldap.NewSearchRequest(
			ldapBaseDN,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			filter,
			[]string{"*"},
			nil,
		)

		sr, err := conn.Search(searchReq)
		if err != nil {
			sendJSON(w, 400, map[string]string{"error": fmt.Sprintf("Search failed: %s", err)})
			return
		}

		type entryResult struct {
			DN         string            `json:"dn"`
			Attributes map[string]string `json:"attributes"`
		}
		entries := make([]entryResult, 0, len(sr.Entries))
		for _, e := range sr.Entries {
			attrs := make(map[string]string)
			for _, a := range e.Attributes {
				attrs[a.Name] = a.Values[0]
			}
			entries = append(entries, entryResult{DN: e.DN, Attributes: attrs})
		}

		sendJSON(w, 200, map[string]any{
			"count":   len(entries),
			"entries": entries,
		})
	})

	addr := fmt.Sprintf("127.0.0.1:%s", getEnv("PORT", "8000"))
	log.Printf("LDAP Auth Server at http://%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
