---
name: Custom JWT Implementation Patterns (Python)
description: PyJWT / python-jose / authlib verify options, alg pinning, JWKS, key rotation, refresh-token rotation, session-token-as-JWT anti-pattern
applies_to:
  - dependency: PyJWT
  - dependency: python-jose
  - dependency: authlib
  - dependency: jwcrypto
  - feature: jwt
version: 1
last_updated: 2026-04-30
---

# Custom JWT Implementation Patterns (Python)

Apply when project verifies / issues JWTs directly with `PyJWT`, `python-jose`, `authlib`, or
`jwcrypto`. Sister module to `node-security/modules/custom-jwt.md`. Frameworks with their own
JWT integration (`fastapi-users`, DRF SimpleJWT, django-rest-framework-simplejwt) layer on top
of one of these libraries; the same principles apply, but check the framework module first
for opinionated defaults.

`python-jose` is **lightly maintained** (last meaningful release pre-2024); prefer `PyJWT`
or `authlib.jose` for new code. `python-jose` had multiple unfixed advisories around algorithm
confusion - see CVEs at end.

## 1. Verification

**Red Flags:**
```python
# VULNERABLE - no algorithms specified (PyJWT >=2.0 raises; python-jose accepts)
jwt.decode(token, key)

# VULNERABLE - signature disabled
jwt.decode(token, key, options={"verify_signature": False})
jwt.decode(token, options={"verify_signature": False})              # PyJWT 2: key not required when sig off
jose.jwt.decode(token, key, options={"verify_signature": False})

# VULNERABLE - decode without verify (returns claims regardless of signature)
unverified = jwt.get_unverified_claims(token)                       # python-jose
unverified = jwt.decode(token, options={"verify_signature": False}) # PyJWT
# never trust these for authz

# VULNERABLE - HS / RS algorithm confusion
jwt.decode(token, public_key_pem, algorithms=["HS256", "RS256"])
# attacker signs with HS256 using the public key as the secret -> verifies as if RS256
# python-jose <3.4.0 had this exact CVE (CVE-2024-33663)

# VULNERABLE - no aud / iss
jwt.decode(token, key, algorithms=["RS256"])

# SAFE
jwt.decode(
    token,
    key,
    algorithms=["RS256"],
    audience="my-api",
    issuer="https://issuer.example",
    leeway=30,                                                      # 30s clock skew, not minutes
    options={"require": ["exp", "iat", "aud", "iss", "sub"]},
)
```

**Checklist:**
- [ ] `algorithms=` always passed explicitly; never trust the JWT `alg` header
- [ ] `none` algorithm rejected (do not include in `algorithms=`)
- [ ] HS and RS not both accepted with the same key material (algorithm confusion)
- [ ] `audience=` and `issuer=` validated; `options={"require": [...]}` lists required claims
- [ ] `exp` enforced; `leeway` bounded to ≤60s
- [ ] `jwt.get_unverified_claims` / `verify_signature=False` never substituted for `decode` in security-relevant code
- [ ] `python-jose` pinned ≥3.4.0 (CVE-2024-33663 algorithm confusion) AND ≥3.4.0 (CVE-2024-33664 JWE decompression bomb); migration to `PyJWT` / `authlib.jose` preferred

## 2. Signing

**Red Flags:**
```python
# VULNERABLE - HMAC with weak / committed secret
jwt.encode(payload, "secret", algorithm="HS256")
jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")        # Django SECRET_KEY: rotate-aware? leakable in error pages?

# VULNERABLE - no expiration
jwt.encode(payload, key, algorithm="RS256")                        # never expires
jwt.encode({"sub": uid}, key, algorithm="RS256")                   # missing exp/iat/jti
```

**Checklist:**
- [ ] HMAC keys ≥256 bits of entropy (`secrets.token_bytes(32)`); from secret manager, not the literal string `"secret"`
- [ ] Asymmetric keys: private key on issuer only; public key distributed via JWKS or pinned in verifier config
- [ ] `exp` always set (1h-24h typical for access tokens; refresh tokens longer with rotation)
- [ ] `iat` (issued-at) included; helps with revocation by issued-before window
- [ ] `jti` (unique ID) included for one-time-use tokens (password reset, magic link, email change)
- [ ] `nbf` ("not-before") set when token must not be valid immediately

## 3. JWKS Fetch / kid Handling

**Red Flags:**
```python
# VULNERABLE - JWKS fetched over plain HTTP
jwks_uri = "http://issuer/.well-known/jwks.json"                   # MITM swaps keys
jwks = requests.get(jwks_uri).json()

# VULNERABLE - kid used as path component (path traversal / SSRF)
unverified_header = jwt.get_unverified_header(token)
key = requests.get(f"{jwks_uri}/{unverified_header['kid']}").json()

# VULNERABLE - SSRF via attacker-controlled iss claim
unverified = jwt.decode(token, options={"verify_signature": False})
jwks = requests.get(f"{unverified['iss']}/.well-known/jwks.json").json()
# attacker sets iss to http://169.254.169.254/... or internal service

# VULNERABLE - no cache; rotation flood DoS
def get_key(kid):
    return requests.get(JWKS_URI).json()                            # every request hits issuer

# SAFE - PyJWT has a JWKS client with caching
from jwt import PyJWKClient
jwks_client = PyJWKClient(
    "https://issuer.example/.well-known/jwks.json",                 # static, HTTPS
    cache_keys=True,
    lifespan=3600,
    max_cached_keys=16,
)
signing_key = jwks_client.get_signing_key_from_jwt(token)
jwt.decode(token, signing_key.key, algorithms=["RS256"], audience="my-api", issuer="https://issuer.example")

# SAFE - authlib
from authlib.jose import jwt as ajwt, JsonWebKey
keyset = JsonWebKey.import_key_set(cached_jwks_json)               # cached, refreshed out-of-band
claims = ajwt.decode(token, keyset, claims_options={"iss": {"essential": True, "value": "https://issuer.example"}})
```

**Checklist:**
- [ ] JWKS URI is HTTPS and pinned to a known issuer host - never derived from the JWT's own `iss` claim
- [ ] `kid` lookup is a key-by-ID match within the JWKS document, not a URL path component or filename
- [ ] JWKS responses cached with bounded TTL (PyJWT `PyJWKClient(lifespan=...)` or external cache)
- [ ] Cache key includes the URI; max-cached-keys bounded so rotation cannot force unbounded memory
- [ ] If multiple issuers federated, allowlist of trusted issuer URIs - not "any URL in the token"

## 4. Key Rotation

**Checklist:**
- [ ] JWKS publishes both old and new keys during overlap window
- [ ] Issuer signs with new key after rotation; old key remains in JWKS for ≥ max token lifetime
- [ ] Verifier accepts any active `kid` in JWKS; expired `kid`s removed after the window
- [ ] HMAC rotation: verifier accepts a list of secrets during overlap (`hmac.compare_digest` against each); attempts ordered new-then-old

## 5. Refresh-Token Rotation

**Red Flags:**
```python
# VULNERABLE - long-lived refresh token, never rotates
refresh = jwt.encode({"sub": uid, "exp": now + 30 * 86400}, key, algorithm="RS256")

# VULNERABLE - refresh token reuse not detected
def refresh_endpoint(rt: str):
    claims = jwt.decode(rt, key, algorithms=["RS256"], audience="refresh", issuer=ISSUER)
    return {"access": issue_access(claims["sub"]), "refresh": rt}   # same RT reused infinitely

# SAFE - rotation + reuse detection
def refresh_endpoint(rt: str):
    claims = jwt.decode(rt, key, algorithms=["RS256"], audience="refresh", issuer=ISSUER)
    row = db.refresh_tokens.find_one_and_update(
        {"jti": claims["jti"], "used": False},
        {"$set": {"used": True, "used_at": utcnow()}},
    )
    if row is None:
        # presented but already used: token theft suspected
        db.refresh_tokens.update_many({"family_id": claims["family_id"]}, {"$set": {"revoked": True}})
        raise HTTPException(401, "refresh reuse")
    new_jti = secrets.token_urlsafe(16)
    db.refresh_tokens.insert_one({"jti": new_jti, "family_id": claims["family_id"], "user_id": claims["sub"], "used": False})
    return {
        "access": issue_access(claims["sub"]),
        "refresh": jwt.encode({"sub": claims["sub"], "jti": new_jti, "family_id": claims["family_id"], ...}, key, algorithm="RS256"),
    }
```

**Checklist:**
- [ ] Refresh tokens rotate on each use; old `jti` marked used in DB atomically
- [ ] Reuse detection: a previously-used refresh token revokes the entire family (mitigates theft)
- [ ] Refresh tokens stored as opaque DB rows (preferred) OR as JWTs with a server-side `jti`/`family_id` index; never stateless JWTs
- [ ] Refresh-token endpoint rate-limited per user / IP
- [ ] Logout revokes the active refresh-token family (`UPDATE refresh_tokens SET revoked=true WHERE family_id=...`)

## 6. Session-Token-As-JWT Anti-Pattern

If JWTs are used as session tokens stored in cookies:

**Checklist:**
- [ ] Cookie has `httponly=True`, `secure=True`, `samesite="lax"` (or `"strict"` for high-value)
- [ ] Server-side revocation list (deny list of `jti`) - JWTs are stateless and cannot be revoked otherwise
- [ ] OR `expires_in` very short (5-15 min) so revocation lag is bounded; relies on refresh rotation
- [ ] Logout revokes refresh tokens AND adds active-access-token `jti` to deny list (or accepts the short remaining lifetime)
- [ ] Sensitive operations (password change, MFA enrollment, email change) require fresh authentication - check `iat` / `auth_time` claim and re-prompt if older than threshold

## 7. Claim Validation

**Checklist:**
- [ ] `sub` (subject) treated as opaque ID; validated for shape (UUID / int / ObjectId) before DB query
- [ ] Custom claims (`role`, `tenant_id`, `permissions`) trusted only if the issuer is your own service - federated tokens may carry attacker-influenced claims
- [ ] Token `aud` matched against the consuming service's expected audience - prevents tokens issued for service A being replayed at service B
- [ ] Nested JWT (JWT-in-JWT, `cty: JWT`) verified at each layer; do not trust inner claims based on outer signature alone
- [ ] `email_verified` claim from federated IdPs treated with caution - only trust from IdPs that actually verify (Google, Microsoft, well-known SaaS); not blanket-trusted across providers

## 8. JWE (Encrypted JWT) Specifics

**Red Flags:**
```python
# VULNERABLE - python-jose <3.4.0: zip="DEF" (deflate) decompression bomb (CVE-2024-33664)
encrypted = jose.jwe.encrypt(plaintext, key, algorithm="dir", encryption="A256GCM", zip="DEF")

# VULNERABLE - RSA1_5 key wrap (Bleichenbacher-shaped attacks; deprecated in JOSE)
jwe = jose.jwe.encrypt(payload, public_key, algorithm="RSA1_5", encryption="A256CBC-HS512")
```

**Checklist:**
- [ ] Key-wrap algorithms: `RSA-OAEP-256`, `ECDH-ES+A256KW`, or `dir` with strong AEAD; not `RSA1_5`
- [ ] Content encryption: `A256GCM` or `A128GCM` (AEAD); avoid `A256CBC-HS512` unless needed
- [ ] Decompression (`zip="DEF"`) capped server-side; reject inputs whose decompressed payload exceeds a hard byte limit
- [ ] `python-jose` ≥3.4.0 for the JWE-related fixes; consider `authlib` or `jwcrypto` instead

## References

- RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- RFC 7515 (JWS), RFC 7516 (JWE), RFC 7518 (JWA), RFC 7517 (JWK)
- PyJWT: https://pyjwt.readthedocs.io/
- authlib JOSE: https://docs.authlib.org/en/latest/jose/
- Algorithm confusion: https://portswigger.net/web-security/jwt/algorithm-confusion
- python-jose CVE-2024-33663 (alg confusion): https://nvd.nist.gov/vuln/detail/CVE-2024-33663
- python-jose CVE-2024-33664 (JWE bomb): https://nvd.nist.gov/vuln/detail/CVE-2024-33664
