---
name: OAuth2 Security Patterns
description: PKCE, redirect URI validation, token storage, refresh rotation, scope, and JWT handling
applies_to:
  - feature: oauth2
  - feature: oidc
  - dependency: authlib
  - dependency: oauthlib
  - dependency: requests-oauthlib
  - dependency: django-oauth-toolkit
  - dependency: fastapi-users
version: 1
last_updated: 2026-04-29
---

# OAuth2 Security Patterns

Optional module for the `/security` skill. Apply when the project implements OAuth2 as a client (consuming tokens from external providers) or as a server (issuing tokens).

## 1. Authorization Code Flow

**Red Flags:**
```python
# VULNERABLE - no PKCE, authorization code interception possible
auth_url = f"{provider}/authorize?client_id={cid}&redirect_uri={ruri}&response_type=code"

# SAFE - PKCE with S256
code_verifier = secrets.token_urlsafe(64)
code_challenge = base64url(sha256(code_verifier))
auth_url = f"{provider}/authorize?...&code_challenge={code_challenge}&code_challenge_method=S256"
```

**Checklist:**
- [ ] PKCE enforced on all authorization code flows (required for public clients, strongly recommended for confidential)
- [ ] `code_challenge_method` is `S256`, never `plain`
- [ ] Authorization code is single-use and short-lived (< 10 min)
- [ ] Code verifier stored server-side (session), not round-tripped through client

## 2. Redirect URI Validation

**Red Flags:**
```python
# VULNERABLE - prefix match allows open redirect
if redirect_uri.startswith(registered_uri):
    allow()  # https://app.com.evil.com matches https://app.com

# VULNERABLE - no validation at all
redirect_uri = request.args.get("redirect_uri")
return redirect(f"{redirect_uri}?code={code}")

# SAFE - exact match
if redirect_uri not in client.registered_redirect_uris:
    raise InvalidRequest("redirect_uri mismatch")
```

**Checklist:**
- [ ] Redirect URIs validated by exact string match against pre-registered list
- [ ] No prefix matching, no wildcard subdomains, no regex matching
- [ ] Redirect URI compared at both authorization AND token exchange
- [ ] `localhost` / `127.0.0.1` URIs restricted to development environments

## 3. Token Storage

**Checklist:**
- [ ] Access tokens never stored in localStorage (XSS-exfiltrable)
- [ ] Refresh tokens stored server-side or in HttpOnly/Secure cookies
- [ ] Tokens not logged, not included in error responses, not in URL parameters
- [ ] Database-stored tokens encrypted at rest or hashed (store hash, compare hash)
- [ ] Token columns have appropriate length limits

## 4. Refresh Token Rotation

**Checklist:**
- [ ] Refresh tokens are single-use (rotated on each use)
- [ ] Old refresh token invalidated when new one issued
- [ ] Reuse of an already-rotated refresh token revokes the entire token family (replay detection)
- [ ] Refresh tokens have absolute expiry (not just sliding)
- [ ] Refresh token grant validates `client_id` matches the original authorization

## 5. Scope Management

**Red Flags:**
```python
# VULNERABLE - client requests elevated scope, server grants without checking
requested_scopes = request.form.get("scope", "").split()
token = issue_token(user, scopes=requested_scopes)  # No validation

# SAFE
allowed = client.allowed_scopes & set(requested_scopes)
if set(requested_scopes) - allowed:
    raise InvalidScope("Requested scope exceeds client allowance")
```

**Checklist:**
- [ ] Token scopes validated against client's registered allowed scopes
- [ ] Scope escalation impossible (refresh token cannot gain scopes not in original grant)
- [ ] Resource endpoints enforce scope requirements (not just "has a valid token")
- [ ] `openid` scope properly gated if OIDC is supported

## 6. Client Authentication

**Checklist:**
- [ ] Client secrets treated as credentials (hashed or encrypted at rest, not logged)
- [ ] Client secret rotation supported without downtime
- [ ] `client_secret_post` preferred over `client_secret_basic` (avoids URL-encoding issues)
- [ ] Public clients (SPAs, mobile) never issued client secrets; use PKCE instead

## 7. Token Endpoint Security

**Checklist:**
- [ ] Token endpoint rate-limited (prevents brute-force of authorization codes)
- [ ] `grant_type` validated against client's allowed grant types
- [ ] Implicit grant (`response_type=token`) disabled unless explicitly required
- [ ] `state` parameter required and validated (CSRF protection for authorization flow)
- [ ] `nonce` validated in ID tokens when using OIDC

## 8. JWT-specific (if tokens are JWTs)

**Red Flags:**
```python
# VULNERABLE - no algorithm restriction
payload = jwt.decode(token, key)

# VULNERABLE - accepts "none" algorithm
payload = jwt.decode(token, key, algorithms=["HS256", "none"])

# SAFE
payload = jwt.decode(token, key, algorithms=["RS256"])
```

**Checklist:**
- [ ] Algorithm explicitly specified at verification (no `alg` header trust)
- [ ] `none` algorithm rejected
- [ ] `HS256` not accepted when `RS256` is expected (algorithm confusion attack)
- [ ] `iss`, `aud`, `exp` claims validated
- [ ] Key/secret has sufficient entropy (>= 256 bits for HMAC)
- [ ] JWK endpoint (if exposed) does not leak private keys
