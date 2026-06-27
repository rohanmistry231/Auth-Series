"""SAML 2.0 Service Provider (SP).

Endpoints:
  GET  /login    → Redirect to IdP SSO
  POST /acs      → Assertion Consumer Service — receive SAML Response
  GET  /metadata → SP metadata XML
"""

import os
import uuid
from base64 import b64decode
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from lxml import etree
from signxml import XMLVerifier

app = FastAPI(title="SAML 2.0 SP Example")

SP_ENTITY_ID = "http://localhost:8001/metadata"
SP_ACS_URL = "http://localhost:8001/acs"
IDP_SSO_URL = "http://localhost:8000/sso"
IDP_ENTITY_ID = "http://localhost:8000/metadata"

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

cert_builder = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAML SP")]))
    .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAML SP")]))
    .public_key(public_key)
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.now(timezone.utc))
    .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
)
certificate = cert_builder.sign(private_key, hashes.SHA256())
SP_CERT_PEM = certificate.public_bytes(serialization.Encoding.PEM).decode()

seen_assertion_ids: set[str] = set()
sessions: dict[str, dict] = {}


@app.get("/login")
def login():
    return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:500px;margin:40px auto">
<h2>SAML SP — SSO Login</h2>
<p><a href="{IDP_SSO_URL}">Sign in via SAML IdP</a></p>
</body></html>""")


@app.post("/acs")
def acs(SAMLResponse: str = Form(...), RelayState: str = Form("")):
    try:
        decoded = b64decode(SAMLResponse)
        root = etree.fromstring(decoded)

        ns_protocol = "urn:oasis:names:tc:SAML:2.0:protocol"
        ns_saml = "urn:oasis:names:tc:SAML:2.0:assertion"

        # Find assertion (signed)
        assertion = root.find(f".//{{{ns_saml}}}Assertion")
        if assertion is None:
            return HTMLResponse("No assertion found", status_code=400)

        # Verify the assertion's XML signature
        verified_data = XMLVerifier().verify(assertion).signed_xml
        verified_assertion = etree.fromstring(verified_data)

        issuer = verified_assertion.find(f"{{{ns_saml}}}Issuer")
        if issuer is None or issuer.text != IDP_ENTITY_ID:
            return HTMLResponse(f"Issuer mismatch: {issuer.text if issuer is not None else 'none'}", status_code=400)

        assertion_id = verified_assertion.get("ID", "")
        if assertion_id in seen_assertion_ids:
            return HTMLResponse("Assertion replay detected", status_code=400)
        seen_assertion_ids.add(assertion_id)

        name_id_elem = verified_assertion.find(f".//{{{ns_saml}}}NameID")
        name_id = name_id_elem.text if name_id_elem is not None else "unknown"

        attributes = {}
        for attr in verified_assertion.findall(f".//{{{ns_saml}}}Attribute"):
            name = attr.get("Name", "")
            val = attr.find(f"{{{ns_saml}}}AttributeValue")
            if val is not None:
                attributes[name] = val.text

        conditions = verified_assertion.find(f"{{{ns_saml}}}Conditions")
        if conditions is not None:
            not_before_str = conditions.get("NotBefore")
            not_on_or_after_str = conditions.get("NotOnOrAfter")
            now = datetime.now(timezone.utc)

            if not_on_or_after_str:
                not_on_or_after = datetime.fromisoformat(not_on_or_after_str)
                if now > not_on_or_after:
                    return HTMLResponse("Assertion expired", status_code=400)

            audience_elem = verified_assertion.find(f".//{{{ns_saml}}}Audience")
            if audience_elem is not None and audience_elem.text != SP_ENTITY_ID:
                return HTMLResponse(f"Audience mismatch: {audience_elem.text}", status_code=400)

        session_id = str(uuid.uuid4())
        sessions[session_id] = {
            "name_id": name_id,
            "attributes": attributes,
        }

        return HTMLResponse(f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:600px;margin:40px auto">
<h2>✅ SAML Authentication Successful</h2>
<table border="1" cellpadding="8" style="border-collapse:collapse">
<tr><th>Attribute</th><th>Value</th></tr>
<tr><td>NameID</td><td>{name_id}</td></tr>
{''.join(f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in attributes.items())}
</table>
<p><a href="/login">Back to login</a></p>
</body></html>""")

    except Exception as e:
        return HTMLResponse(f"SAML processing error: {e}", status_code=400)


@app.get("/metadata")
def metadata():
    ns_md = "urn:oasis:names:tc:SAML:2.0:metadata"
    ns_ds = "http://www.w3.org/2000/09/xmldsig#"

    md = etree.Element(f"{{{ns_md}}}EntityDescriptor", nsmap={"md": ns_md, "ds": ns_ds})
    md.set("entityID", SP_ENTITY_ID)

    sp_sso = etree.SubElement(md, f"{{{ns_md}}}SPSSODescriptor")
    sp_sso.set("AuthnRequestsSigned", "false")
    sp_sso.set("WantAssertionsSigned", "true")
    sp_sso.set("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol")

    key_descriptor = etree.SubElement(sp_sso, f"{{{ns_md}}}KeyDescriptor")
    key_descriptor.set("use", "signing")
    key_info = etree.SubElement(key_descriptor, f"{{{ns_ds}}}KeyInfo")
    key_name = etree.SubElement(key_info, f"{{{ns_ds}}}X509Data")
    cert_elem = etree.SubElement(key_name, f"{{{ns_ds}}}X509Certificate")
    cert_no_headers = SP_CERT_PEM.replace("-----BEGIN CERTIFICATE-----\n", "").replace("\n-----END CERTIFICATE-----\n", "").replace("\n", "")
    cert_elem.text = cert_no_headers

    acs = etree.SubElement(sp_sso, f"{{{ns_md}}}AssertionConsumerService")
    acs.set("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    acs.set("Location", SP_ACS_URL)
    acs.set("index", "0")

    return HTMLResponse(
        content=etree.tostring(md, xml_declaration=True, encoding="UTF-8", standalone=True).decode(),
        media_type="application/xml",
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sp:app", host="0.0.0.0", port=8001, reload=False)
