package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	idpEntityID = "http://localhost:8000/metadata"
	spACSURL    = "http://localhost:8001/acs"
	spEntityID  = "http://localhost:8001/metadata"
	idpKey      *rsa.PrivateKey
	idpCertPEM  string
)

func init() {
	var err error
	idpKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "SAML IdP"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:         true,
		BasicConstraintsValid: true,
	}
	certBytes, _ := x509.CreateCertificate(rand.Reader, template, template, &idpKey.PublicKey, idpKey)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	idpCertPEM = string(certPEM)
}

var users = map[string]map[string]string{
	"alice": {
		"password":   getEnv("ALICE_PASSWORD", "password-alice"),
		"email":      "alice@example.com",
		"role":       "admin",
		"department": "Engineering",
	},
}

func getEnv(k, f string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return f
}

func signXML(data string) string {
	hash := sha256.Sum256([]byte(data))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, idpKey, crypto.SHA256, hash[:])
	return base64.StdEncoding.EncodeToString(sig)
}

func makeSAMLResponse(username string) string {
	user := users[username]
	now := time.Now().UTC().Format(time.RFC3339)
	expiry := time.Now().UTC().Add(1 * time.Hour).Format(time.RFC3339)

	assertionXML := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="ASSERTION_%d" IssueInstant="%s" Version="2.0">
	<saml:Issuer>%s</saml:Issuer>
	<saml:Subject>
		<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
		<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
			<saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"/>
		</saml:SubjectConfirmation>
	</saml:Subject>
	<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
		<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
	</saml:Conditions>
	<saml:AuthnStatement AuthnInstant="%s">
		<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
	</saml:AuthnStatement>
	<saml:AttributeStatement>
		<saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
		<saml:Attribute Name="role"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
		<saml:Attribute Name="department"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>
	</saml:AttributeStatement>
</saml:Assertion>`,
		time.Now().UnixNano(), now,
		idpEntityID,
		user["email"],
		expiry, spACSURL,
		now, expiry, spEntityID,
		now,
		user["email"], user["role"], user["department"])

	signature := signXML(assertionXML)

	signedAssertion := fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="ASSERTION_%d" IssueInstant="%s" Version="2.0">
	<saml:Issuer>%s</saml:Issuer>
	<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
		<ds:SignedInfo>
			<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
			<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
			<ds:Reference URI="">
				<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
				<ds:DigestValue>%s</ds:DigestValue>
			</ds:Reference>
		</ds:SignedInfo>
		<ds:SignatureValue>%s</ds:SignatureValue>
	</ds:Signature>%s`,
		time.Now().UnixNano(), now, idpEntityID,
		base64.StdEncoding.EncodeToString([]byte(assertionXML)),
		signature,
		strings.Join(strings.SplitAfterN(assertionXML, "<saml:Issuer>", 2)[1:], ""),
	)

	responseXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="RESPONSE_%d" Version="2.0" IssueInstant="%s" Destination="%s">
	<saml:Issuer>%s</saml:Issuer>
	<samlp:Status>
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	</samlp:Status>
	%s
</samlp:Response>`, time.Now().UnixNano(), now, spACSURL, idpEntityID, signedAssertion)

	return responseXML
}

func ssoHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		w.Write([]byte(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>SAML IdP — Sign In</h2>
<form method="post" action="/sso">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Sign In</button></p>
</form></body></html>`))
		return
	}

	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, ok := users[username]
		if !ok || user["password"] != password {
			w.WriteHeader(401)
			w.Write([]byte("Invalid credentials"))
			return
		}

		samlResp := makeSAMLResponse(username)
		samlB64 := base64.StdEncoding.EncodeToString([]byte(samlResp))

		w.Write([]byte(fmt.Sprintf(`<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="post" action="%s">
<input type="hidden" name="SAMLResponse" value="%s">
<input type="hidden" name="RelayState" value="">
<noscript><button type="submit">Continue</button></noscript>
</form></body></html>`, spACSURL, samlB64)))
		return
	}
}

func metadataHandler(w http.ResponseWriter, r *http.Request) {
	certB64 := base64.StdEncoding.EncodeToString(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: idpCertPEM}),
	)

	w.Header().Set("Content-Type", "application/xml")
	fmt.Fprintf(w, `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="%s">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="http://localhost:8000/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`, idpEntityID, certB64)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/sso", ssoHandler)
	mux.HandleFunc("/metadata", metadataHandler)

	addr := fmt.Sprintf("0.0.0.0:%s", getEnv("PORT", "8000"))
	log.Printf("SAML IdP at http://localhost:%s", getEnv("PORT", "8000"))
	log.Fatal(http.ListenAndServe(addr, mux))
}

var _ = crypto.SHA256
