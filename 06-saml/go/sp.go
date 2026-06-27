package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	spEntityID  = "http://localhost:8001/metadata"
	spACSURL    = "http://localhost:8001/acs"
	idpEntityID = "http://localhost:8000/metadata"
	idpSSOURL   = "http://localhost:8000/sso"
)

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>SAML SP — SSO Login</h2>
<p><a href="%s">Sign in via SAML IdP</a></p>
</body></html>`, idpSSOURL)))
}

func acsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}

	body, _ := io.ReadAll(r.Body)
	r.ParseForm()

	samlB64 := r.FormValue("SAMLResponse")
	if samlB64 == "" {
		w.WriteHeader(400)
		w.Write([]byte("Missing SAMLResponse"))
		return
	}

	samlXML, err := base64.StdEncoding.DecodeString(samlB64)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("Invalid base64"))
		return
	}

	xmlStr := string(samlXML)

	// Basic validation — extract values
	extract := func(tag string) string {
		start := strings.Index(xmlStr, "<"+tag+">")
		if start == -1 {
			start = strings.Index(xmlStr, "<saml:"+tag+">")
			if start == -1 {
				return ""
			}
			start += len("<saml:" + tag + ">")
		} else {
			start += len("<" + tag + ">")
		}
		end := strings.Index(xmlStr[start:], "</")
		if end == -1 {
			return ""
		}
		return strings.TrimSpace(xmlStr[start : start+end])
	}

	issuer := extract("Issuer")
	if issuer != idpEntityID {
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf("Issuer mismatch: %s", issuer)))
		return
	}

	nameID := extract("NameID")
	if nameID == "" {
		nameID = "unknown"
	}

	email := extract("AttributeValue")
	role := ""
	department := ""

	// Get all attribute values
	parts := strings.Split(xmlStr, "<saml:AttributeValue>")
	if len(parts) > 1 {
		vals := make([]string, 0)
		for _, p := range parts[1:] {
			end := strings.Index(p, "</")
			if end != -1 {
				vals = append(vals, p[:end])
			}
		}
		if len(vals) > 0 {
			email = vals[0]
		}
		if len(vals) > 1 {
			role = vals[1]
		}
		if len(vals) > 2 {
			department = vals[2]
		}
	}

	w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>✅ SAML Authentication Successful</h2>
<table border="1" cellpadding="8" style="border-collapse:collapse">
<tr><th>Attribute</th><th>Value</th></tr>
<tr><td>NameID</td><td>%s</td></tr>
<tr><td>email</td><td>%s</td></tr>
<tr><td>role</td><td>%s</td></tr>
<tr><td>department</td><td>%s</td></tr>
</table>
<p><a href="/login">Back to login</a></p>
</body></html>`, nameID, email, role, department))
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", ssoHandler)
	mux.HandleFunc("/acs", acsHandler)

	addr := fmt.Sprintf("0.0.0.0:%s", getEnv("PORT", "8001"))
	log.Printf("SAML SP at http://localhost:%s", getEnv("PORT", "8001"))
	log.Fatal(http.ListenAndServe(addr, mux))
}

var (
	_ = rsa.GenerateKey
	_ = x509.CreateCertificate
	_ = pem.EncodeToMemory
	_ = sha256.New
	_ = big.NewInt
	_ = pkix.Name{}
	_ = rand.Reader
)
