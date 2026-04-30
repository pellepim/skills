---
name: SAML Security Patterns
description: XSW, replay, audience, NotOnOrAfter, IdP key pinning, metadata SSRF, signature wrapping
applies_to:
  - feature: saml
  - dependency: "@node-saml/node-saml"
  - dependency: "@node-saml/passport-saml"
  - dependency: passport-saml
  - dependency: samlify
version: 1
last_updated: 2026-04-30
---

# SAML Security Patterns

Apply when the project consumes SAML assertions (most often as an SP integrating with enterprise
IdPs). Underlying XML signature handling is famously brittle; pin a maintained library and assume
malicious assertion content.

## 1. Signature Validation

**Red Flags:**
```js
// VULNERABLE - signature optional / not enforced on assertion
new SAML({ wantAssertionsSigned: false });
new SAML({ wantAuthnResponseSigned: false });

// VULNERABLE - accepting assertions where only the response is signed (XSW vector)
```

**Checklist:**
- [ ] `wantAssertionsSigned: true` AND `wantAuthnResponseSigned: true` (defense in depth against XSW)
- [ ] Library pinned to a recent maintained version with XSW fixes (`@node-saml/node-saml` ≥4, `samlify` recent)
- [ ] No usage of `passport-saml` < 5 (maintainership moved to `@node-saml`)

## 2. IdP Certificate Pinning

**Red Flags:**
```js
// VULNERABLE - cert fetched dynamically from metadata URL on each request (SSRF + key-substitution risk)
const md = await fetch(metadataUrl).then(r => r.text());

// VULNERABLE - `idpCert` accepts an array of any valid signer
new SAML({ idpCert: [...allCertsFromAnyIdP] });
```

**Checklist:**
- [ ] `idpCert` (or `cert`) pinned to the specific IdP's public certificate; not auto-fetched at request time
- [ ] Certificate rotation handled with overlap: `idpCert: [newCert, oldCert]` during transition
- [ ] Metadata refresh (if used) on a scheduled task, not per-request, and over HTTPS to a pinned host

## 3. Assertion Replay & Conditions

**Red Flags:**
```js
// VULNERABLE - no NotOnOrAfter / NotBefore enforcement
// (most modern libraries enforce by default; verify if a custom verifier is used)

// VULNERABLE - same assertion accepted twice
```

**Checklist:**
- [ ] `NotBefore` and `NotOnOrAfter` enforced; clock skew bounded (60s typical)
- [ ] `Audience` matches our SP entity ID
- [ ] `Recipient` matches our ACS URL
- [ ] `InResponseTo` matches our `AuthnRequest` ID (when SP-initiated)
- [ ] Assertion ID stored as one-time-use (TTL ≥ NotOnOrAfter window) - replay defense
- [ ] `RequestId` / `RelayState` validated; RelayState treated as opaque, validated on callback as relative URL only

## 4. Subject / NameID

**Red Flags:**
```js
// VULNERABLE - using NameID transient/persistent value as DB primary key without isolating per IdP
const userId = assertion.nameID;
```

**Checklist:**
- [ ] Federation key is `(idpEntityId, NameID)` tuple, not just NameID - prevents cross-IdP collisions
- [ ] NameID format checked (`emailAddress` vs `persistent` vs `transient`) and matches your model
- [ ] Email-based linking to existing accounts requires email verified by IdP; otherwise pre-existing account hijack

## 5. SP Signing & Encryption

**Checklist:**
- [ ] SP signs `AuthnRequest` if the IdP requires it (some do)
- [ ] If the IdP encrypts assertions, the SP private key stored in KMS / secret manager, not committed
- [ ] Signing/encryption key rotation supported

## 6. Metadata SSRF

**Red Flags:**
```js
// VULNERABLE - admin endpoint fetches metadata from user-supplied URL
app.post("/sso/configure", async (req) => {
  const md = await fetch(req.body.metadataUrl).then(r => r.text());
  await SsoConfig.create({ metadata: md });
});
```

**Checklist:**
- [ ] Metadata-by-URL is gated behind admin auth AND the URL is fetched via the SSRF guard (see SKILL.md)
- [ ] Prefer admin paste-XML over fetch-by-URL

## 7. Logout (SLO)

**Checklist:**
- [ ] LogoutRequest signed and validated on inbound; signed on outbound
- [ ] LogoutResponse validated; do not accept unsigned LogoutResponses
- [ ] Local session terminated only after IdP confirms logout (or after timeout); avoid premature destruction that
      leaves the IdP session open

## 8. Library Bugs

**Checklist:**
- [ ] `xml-crypto` versions audited for known XSW / signature-wrapping CVEs
- [ ] `xmldom` deprecated; switch to `@xmldom/xmldom` ≥0.8.6 with hardening flags
- [ ] `xml2js` configured to NOT resolve external entities

## References

- OWASP SAML Cheat Sheet
- @node-saml/node-saml: https://github.com/node-saml/node-saml
- XSW background: https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
