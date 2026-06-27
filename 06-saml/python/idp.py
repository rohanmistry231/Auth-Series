"""SAML 2.0 Identity Provider (IdP).

Endpoints:
  GET  /sso          → Login page (simulates SP-initiated SSO)
  POST /sso          → Authenticate user, generate & sign SAML Response
  GET  /metadata     → IdP metadata XML
"""

import os
import uuid
from datetime import datetime, timedelta, timezone
from base64 import b64encode

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from lxml import etree
from signxml import XMLSigner, XMLVerifier

app = FastAPI(title="SAML 2.0 IdP Example")

IDP_ENTITY_ID = "http://localhost:8000/metadata"
SP_ACS_URL = "http://localhost:8001/acs"
SP_ENTITY_ID = "http://localhost:8001/metadata"

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

cert_builder = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAML IdP")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAML IdP")]))
    .public_key(public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
)
certificate = cert_builder.sign(private_key, hashes.SHA256())
CERT_PEM = certificate.public_bytes(serialization.Encoding.PEM).decode()
KEY_PEM = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
).decode()

USERS = {
    "alice": {
        "password": os.environ.get("ALICE_PASSWORD", "password-alice"),
        "email": "alice@example.com",
        "role": "admin",
        "department": "Engineering",
    },
}


def make_saml_response(username: str, acs_url: str) -> str:
    user = USERS[username]
    assertion_id = f"ASSERTION_{uuid.uuid4().hex}"
    response_id = f"RESPONSE_{uuid.uuid4().hex}"
    now = datetime.now(timezone.utc)
    not_before = now - timedelta(minutes=5)
    not_on_or_after = now + timedelta(hours=1)

    # Build assertion XML manually for educational clarity
    ns_saml = "urn:oasis:names:tc:SAML:2.0:assertion"
    ns_protocol = "urn:oasis:names:tc:SAML:2.0:protocol"

    assertion = etree.Element(f"{{{ns_saml}}}Assertion", nsmap={
        "saml": ns_saml,
        "samlp": ns_protocol,
    })
    assertion.set("ID", assertion_id)
    assertion.set("IssueInstant", now.isoformat())
    assertion.set("Version", "2.0")

    issuer = etree.SubElement(assertion, f"{{{ns_saml}}}Issuer")
    issuer.text = IDP_ENTITY_ID

    subject = etree.SubElement(assertion, f"{{{ns_saml}}}Subject")
    name_id = etree.SubElement(subject, f"{{{ns_saml}}}NameID")
    name_id.set("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
    name_id.text = user["email"]

    subj_conf = etree.SubElement(subject, f"{{{ns_saml}}}SubjectConfirmation")
    subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
    subj_conf_data = etree.SubElement(subj_conf, f"{{{ns_saml}}}SubjectConfirmationData")
    subj_conf_data.set("InResponseTo", "")
    subj_conf_data.set("NotOnOrAfter", not_on_or_after.isoformat())
    subj_conf_data.set("Recipient", acs_url)

    conditions = etree.SubElement(assertion, f"{{{ns_saml}}}Conditions")
    conditions.set("NotBefore", not_before.isoformat())
    conditions.set("NotOnOrAfter", not_on_or_after.isoformat())

    audience_restriction = etree.SubElement(conditions, f"{{{ns_saml}}}AudienceRestriction")
    audience = etree.SubElement(audience_restriction, f"{{{ns_saml}}}Audience")
    audience.text = SP_ENTITY_ID

    authn_stmt = etree.SubElement(assertion, f"{{{ns_saml}}}AuthnStatement")
    authn_stmt.set("AuthnInstant", now.isoformat())
    authn_ctx = etree.SubElement(authn_stmt, f"{{{ns_saml}}}AuthnContext")
    authn_ctx_class = etree.SubElement(authn_ctx, f"{{{ns_saml}}}AuthnContextClassRef")
    authn_ctx_class.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"

    attr_stmt = etree.SubElement(assertion, f"{{{ns_saml}}}AttributeStatement")
    for name, value in [("email", user["email"]), ("role", user["role"]), ("department", user["department"])]:
        attr = etree.SubElement(attr_stmt, f"{{{ns_saml}}}Attribute")
        attr.set("Name", name)
        attr_val = etree.SubElement(attr, f"{{{ns_saml}}}AttributeValue")
        attr_val.text = value

    # Sign the assertion
    signer = XMLSigner(
        c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",
        signature_algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        digest_algorithm="http://www.w3.org/2001/04/xmlenc#sha256",
    )
    signed_assertion = signer.sign(assertion, key=KEY_PEM.encode(), cert=CERT_PEM.encode())

    # Wrap in Response
    response = etree.Element(f"{{{ns_protocol}}}Response", nsmap={
        "samlp": ns_protocol,
        "saml": ns_saml,
    })
    response.set("ID", response_id)
    response.set("InResponseTo", "")
    response.set("Version", "2.0")
    response.set("IssueInstant", now.isoformat())
    response.set("Destination", acs_url)

    resp_issuer = etree.SubElement(response, f"{{{ns_saml}}}Issuer")
    resp_issuer.text = IDP_ENTITY_ID
    resp_status = etree.SubElement(response, f"{{{ns_protocol}}}Status")
    resp_status_code = etree.SubElement(resp_status, f"{{{ns_protocol}}}StatusCode")
    resp_status_code.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    response.append(signed_assertion)

    return etree.tostring(response, xml_declaration=True, encoding="UTF-8", standalone=True).decode()


@app.get("/sso")
def sso_get():
    return HTMLResponse("""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:400px;margin:40px auto">
<h2>SAML IdP — Sign In</h2>
<form method="post" action="/sso">
<p><label>Username: <input name="username" value="alice"></label></p>
<p><label>Password: <input name="password" type="password"></label></p>
<p><button type="submit">Sign In</button></p>
</form></body></html>""")


@app.post("/sso")
def sso_post(username: str = Form(...), password: str = Form(...)):
    user = USERS.get(username)
    if not user or user["password"] != password:
        return HTMLResponse("Invalid credentials", status_code=401)

    saml_response = make_saml_response(username, SP_ACS_URL)
    saml_b64 = b64encode(saml_response.encode()).decode()

    return HTMLResponse(f"""<!DOCTYPE html>
<html><body onload="document.forms[0].submit()">
<form method="post" action="{SP_ACS_URL}">
<input type="hidden" name="SAMLResponse" value="{saml_b64}">
<input type="hidden" name="RelayState" value="">
<noscript><button type="submit">Continue</button></noscript>
</form></body></html>""")


@app.get("/metadata")
def metadata():
    ns_md = "urn:oasis:names:tc:SAML:2.0:metadata"
    ns_ds = "http://www.w3.org/2000/09/xmldsig#"

    md = etree.Element(f"{{{ns_md}}}EntityDescriptor", nsmap={"md": ns_md, "ds": ns_ds})
    md.set("entityID", IDP_ENTITY_ID)

    idp_sso = etree.SubElement(md, f"{{{ns_md}}}IDPSSODescriptor")
    idp_sso.set("WantAuthnRequestsSigned", "false")
    idp_sso.set("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")

    key_descriptor = etree.SubElement(idp_sso, f"{{{ns_md}}}KeyDescriptor")
    key_descriptor.set("use", "signing")
    key_info = etree.SubElement(key_descriptor, f"{{{ns_ds}}}KeyInfo")
    key_name = etree.SubElement(key_info, f"{{{ns_ds}}}X509Data")
    cert_elem = etree.SubElement(key_name, f"{{{ns_ds}}}X509Certificate")
    cert_no_headers = CERT_PEM.replace("-----BEGIN CERTIFICATE-----\n", "").replace("\n-----END CERTIFICATE-----\n", "").replace("\n", "")
    cert_elem.text = cert_no_headers

    sso_svc = etree.SubElement(idp_sso, f"{{{ns_md}}}SingleSignOnService")
    sso_svc.set("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    sso_svc.set("Location", "http://localhost:8000/sso")

    return HTMLResponse(
        content=etree.tostring(md, xml_declaration=True, encoding="UTF-8", standalone=True).decode(),
        media_type="application/xml",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("idp:app", host="0.0.0.0", port=8000, reload=False)
