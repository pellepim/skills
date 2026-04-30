---
name: OAuth 2.0 / OIDC Security Patterns
description: PKCE, redirect URI matching, token storage, refresh rotation, scope minimization, JWT id_token validation
applies_to:
  - feature: oauth2
  - feature: oidc
  - dependency: openid-client
  - dependency: simple-oauth2
  - dependency: passport-oauth2
version: 1
last_updated: 2026-04-30
---

# OAuth 2.0 / OIDC Security Patterns

Apply when the project acts as an OAuth client (logging users in via Google/GitHub/etc.) or as an
OAuth provider. Most issues involve state/PKCE, redirect URIs, and ID-token validation.

## 1. State / PKCE

**Red Flags:**
```js
// VULNERABLE - no state, no PKCE
const url = `https://issuer/authorize?client_id=...&redirect_uri=...&response_type=code`;
```

**Checklist:**
- [ ] Authorization request includes `state` (random per-flow, bound to user session, single-use)
- [ ] `state` validated on callback BEFORE the code exchange
- [ ] PKCE used for public clients / SPAs / native apps (`code_challenge`, `code_verifier`); also for confidential
      clients per RFC 9700 best practices
- [ ] `nonce` (OIDC) included in the auth request and validated against the `id_token` `nonce` claim

## 2. Redirect URI

**Red Flags:**
```js
// VULNERABLE - dynamic redirect_uri from user input
const url = `https://issuer/authorize?...&redirect_uri=${req.query.return_to}`;

// VULNERABLE - allowlist with substring match
if (uri.startsWith("https://app.example.com")) accept(uri);     // matches https://app.example.com.attacker.com
```

**Checklist:**
- [ ] `redirect_uri` registered with the IdP is an exact-match allowlist
- [ ] If multiple URIs registered, the IdP checks for full equality (scheme + host + port + path)
- [ ] Application-side: do not pass user-controlled values into `redirect_uri`; use server-side mapping (`?return_to=`
      to internal URL after callback completes)
- [ ] `return_to` / `next` parameter validated as a relative path (see SKILL.md "Redirect Validation")

## 3. Code Exchange / Token Endpoint

**Checklist:**
- [ ] Client authentication on token endpoint (`client_secret_basic` or `client_secret_post` for confidential clients;
      none + PKCE for public clients)
- [ ] Token endpoint called server-side only; `client_secret` never exposed to browser
- [ ] TLS verification enabled on token endpoint requests (`rejectUnauthorized: true`)

## 4. ID Token Validation (OIDC)

**Red Flags:**
```js
// VULNERABLE - decoding without verifying signature
const claims = jwt.decode(idToken);

// VULNERABLE - no audience / issuer / nonce check
jwt.verify(idToken, jwks);
```

**Checklist:**
- [ ] Signature verified against the IdP's JWKS (HTTPS-pinned URI)
- [ ] `iss` matches expected issuer
- [ ] `aud` includes our client_id
- [ ] `azp` (authorized party) matches client_id when multiple audiences
- [ ] `exp`, `iat`, `nbf` enforced
- [ ] `nonce` matches the value sent in the authorization request (replay defense)
- [ ] Algorithm pinned (`RS256` or `ES256` typically); `none` rejected
- [ ] See `modules/custom-jwt.md` for full coverage

## 5. Token Storage

**Red Flags:**
```js
// VULNERABLE - access token stored in localStorage (XSS-readable)
localStorage.setItem("access_token", token);
```

**Checklist:**
- [ ] Browser apps: tokens in `httpOnly` cookies, not localStorage / sessionStorage
- [ ] Server-side: refresh tokens encrypted at rest (KMS or app-level AEAD)
- [ ] Refresh tokens rotated on each use; reuse detection revokes the family

## 6. Scope Minimization

**Checklist:**
- [ ] `scope` requested is the minimum needed; do not request `email profile` if only `openid` is used
- [ ] Sensitive scopes (`https://www.googleapis.com/auth/drive`) only requested when the feature is invoked, not at
      sign-in
- [ ] User-visible consent screen enabled (do not bypass with admin-installed apps unless required)

## 7. Logout / Single Sign-Out

**Checklist:**
- [ ] Local logout clears session AND revokes refresh tokens
- [ ] OIDC RP-initiated logout (`end_session_endpoint`) invoked when supported, with `post_logout_redirect_uri`
      registered
- [ ] Back-channel logout (`backchannel_logout_uri`) implemented if the IdP supports it - propagates IdP-initiated
      logouts to your sessions

## 8. Token Endpoint Auth & Replay

**Checklist:**
- [ ] Authorization codes are single-use; second redemption rejected (PKCE binding ensures this when implemented
      correctly)
- [ ] Token endpoint requests over TLS only
- [ ] `client_secret` not committed; from secret manager

## 9. Acting as Provider

If the project IS the OAuth provider:
- [ ] Authorization code TTL ≤ 60s; single-use
- [ ] `redirect_uri` validation: exact match against registered URIs per client
- [ ] PKCE supported (recommended required for all clients per RFC 9700)
- [ ] Token introspection / revocation endpoints implemented
- [ ] `client_secret` rotation supported (multiple active secrets per client)
- [ ] Rate-limit on `/authorize` and `/token` per client and per user

## References

- RFC 6749 (OAuth 2.0): https://datatracker.ietf.org/doc/html/rfc6749
- RFC 9700 (Best Current Practice for OAuth 2.0 Security): https://datatracker.ietf.org/doc/html/rfc9700
- OpenID Connect Core: https://openid.net/specs/openid-connect-core-1_0.html
