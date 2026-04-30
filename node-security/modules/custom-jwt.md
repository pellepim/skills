---
name: Custom JWT Implementation Patterns
description: jsonwebtoken / jose verify options, alg pinning, JWKS, key rotation, refresh-token rotation, session-token-as-jwt anti-pattern
applies_to:
  - dependency: jsonwebtoken
  - dependency: jose
  - feature: jwt
version: 1
last_updated: 2026-04-30
---

# Custom JWT Implementation Patterns

Apply when the project verifies / issues JWTs directly (not via `@fastify/jwt`, NextAuth, or
Passport's JwtStrategy - those have their own modules; the same principles apply).

## 1. Verification

**Red Flags:**
```js
// VULNERABLE - no algorithms specified
jwt.verify(token, secret);                                      // jsonwebtoken: warns; jose: requires algs

// VULNERABLE - decode without verify
const claims = jwt.decode(token);                               // returns unverified claims; never trust

// VULNERABLE - HS / RS algorithm confusion
jwt.verify(token, publicKeyPem, { algorithms: ["HS256", "RS256"] });
// attacker signs HS256 with publicKey as secret -> verifies as if RS256

// VULNERABLE - missing aud / iss
jwt.verify(token, key, { algorithms: ["RS256"] });

// SAFE
jwt.verify(token, key, {
  algorithms: ["RS256"],
  audience: "my-api",
  issuer: "https://issuer.example",
  clockTolerance: 30,
});
```

**Checklist:**
- [ ] `algorithms:` always passed explicitly; never omitted
- [ ] `none` algorithm rejected (do not include in `algorithms`)
- [ ] HS and RS not both accepted with the same key material (algorithm confusion)
- [ ] `audience` and `issuer` validated
- [ ] `expiresIn` enforced; `clockTolerance` bounded (typical 30-60s)
- [ ] `jwt.decode()` never substituted for `verify()` in security-relevant code

## 2. Signing

**Red Flags:**
```js
// VULNERABLE - HMAC with weak secret
jwt.sign(payload, "secret", { algorithm: "HS256" });

// VULNERABLE - no expiration
jwt.sign(payload, key, { algorithm: "RS256" });                 // never expires
```

**Checklist:**
- [ ] HMAC keys ≥256 bits of entropy (random, not "secret"); from secret manager
- [ ] Asymmetric keys: private key on issuer only; public key distributed via JWKS or pinned
- [ ] `expiresIn` always set (1h-24h typical for access tokens; refresh tokens longer with rotation)
- [ ] `iat` (issued-at) included; helps with revocation by issued-before window
- [ ] `jti` (unique ID) included for one-time-use tokens (password reset, magic link)

## 3. JWKS Fetch / kid Handling

**Red Flags:**
```js
// VULNERABLE - JWKS fetched over plain HTTP, or kid used as path
const jwksUri = `http://issuer/.well-known/jwks.json`;
const key = await fetch(`${jwksUri}/${decoded.header.kid}`).then(r => r.json());

// VULNERABLE - SSRF via attacker-controlled iss claim
const jwksUri = `${decoded.payload.iss}/.well-known/jwks.json`;
const jwks = await fetch(jwksUri).then(r => r.json());
```

**Checklist:**
- [ ] JWKS URI is HTTPS and pinned to a known issuer host - never derived from the JWT's own claims
- [ ] `kid` lookup is a key-by-ID match within the JWKS document, not used as a path component
- [ ] JWKS responses cached with bounded TTL; cache key includes the URI
- [ ] Use `jose.createRemoteJWKSet(url)` or `jwks-rsa` rate-limit + cache options - prevents DoS via repeated rotation

## 4. Key Rotation

**Checklist:**
- [ ] JWKS publishes both old and new keys during overlap window
- [ ] Issuer signs with new key after rotation; old key remains in JWKS for ≥ max token lifetime
- [ ] Verifier accepts any active `kid` in JWKS; expired `kid`s removed after the window

## 5. Refresh-Token Rotation

**Red Flags:**
```js
// VULNERABLE - long-lived refresh token never rotates; theft = persistent access
const refresh = jwt.sign({ sub }, key, { expiresIn: "30d" });

// VULNERABLE - refresh token reuse not detected
async function refresh(rt) {
  const claims = jwt.verify(rt, key);
  return { access: issueAccess(claims.sub), refresh: rt };      // same RT reused infinitely
}
```

**Checklist:**
- [ ] Refresh tokens rotate on each use; old token marked used in DB
- [ ] Reuse detection: if a previously-used refresh token is presented, revoke the entire token family
- [ ] Refresh tokens stored as opaque values (DB row) or as JWTs with a serial/family ID; not as bearer JWTs without
      server-side state
- [ ] Refresh-token endpoint rate-limited

## 6. Session-Token-As-JWT Anti-Pattern

If JWTs are used as session tokens stored in cookies:
- [ ] `httpOnly`, `secure`, `sameSite` flags on the cookie
- [ ] Server-side revocation list (deny list of `jti`) - JWTs are stateless and cannot be revoked otherwise; OR keep
      `expiresIn` very short (5-15 min) and rely on rotation
- [ ] Logout revokes refresh tokens AND adds access-token `jti` to deny list (or accepts the short remaining lifetime)
- [ ] Sensitive operations (password change, MFA enrollment) require fresh authentication - check `iat` / `auth_time`
      claim

## 7. Claim Validation

**Checklist:**
- [ ] `sub` (subject) treated as opaque ID; never used as DB query without validation
- [ ] Custom claims (`role`, `tenantId`) trusted only if the issuer is your own service - federated tokens may carry
      attacker-influenced claims
- [ ] Nested JWT (JWT-in-JWT) verified at each layer; do not trust inner claims based on outer signature alone

## References

- RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- jose library: https://github.com/panva/jose
- Algorithm confusion: https://portswigger.net/web-security/jwt/algorithm-confusion
