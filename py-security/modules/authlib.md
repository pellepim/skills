---
name: Authlib Security Patterns
description: Authlib client/provider integrations, ResourceProtector, BearerTokenValidator, token endpoint auth, ID-token validation
applies_to:
  - dependency: authlib
version: 1
last_updated: 2026-04-30
---

# Authlib Security Patterns

Apply when project uses `authlib`. Authlib spans OAuth client, OAuth/OIDC server, JOSE, and
framework integrations (Flask, Django, FastAPI via Starlette). This module covers Authlib-
specific knobs. For protocol-level OAuth2/OIDC concerns, see `oauth2.md`. For raw JOSE / JWT
verification, see `custom-jwt.md`.

## 1. Client: OAuth Registration

**Red Flags:**
```python
# VULNERABLE - client_secret hardcoded
oauth.register(
    name="google",
    client_id="...",
    client_secret="hardcoded-secret",                              # commit risk
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
)

# VULNERABLE - unpinned issuer / discovery URL pulled at request time without TLS pin
oauth.register(name="dynamic", server_metadata_url=user_input)     # never

# VULNERABLE - missing scopes / nonce / state defaults overridden
client_kwargs={"scope": "openid email"}                            # OK; explicit
# But if you removed authlib's default state/nonce handling, CSRF risk re-emerges

# SAFE
oauth.register(
    name="google",
    client_id=os.environ["GOOGLE_CLIENT_ID"],
    client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)
```

**Checklist:**
- [ ] `client_id` / `client_secret` from env or secret manager; not in `settings.py` / `config.py` / VCS
- [ ] `server_metadata_url` is a static, HTTPS URL pinned to the trusted IdP; never derived from user input or runtime config
- [ ] `client_kwargs["scope"]` minimized; do not request `openid offline_access admin` blanket scopes
- [ ] PKCE enabled for public clients (`code_challenge_method="S256"` - Authlib handles when supported by provider)
- [ ] OIDC: `nonce` parameter generated and stored in session; verified on `parse_id_token`
- [ ] State parameter not disabled by custom override - default `authorize_redirect` includes it

## 2. Client: Authorization & Callback

**Red Flags:**
```python
# VULNERABLE - parse_id_token without nonce check
token = await oauth.google.authorize_access_token(request)
user_info = await oauth.google.parse_id_token(request, token)      # if you skip nonce= or use a stale value, replay possible

# VULNERABLE - authorize_redirect with attacker-controlled redirect_uri
@app.route("/login")
def login():
    return oauth.google.authorize_redirect(redirect_uri=request.args["return_to"])
```

**Checklist:**
- [ ] `redirect_uri` value pinned server-side or validated against an allowlist; not taken from request
- [ ] `parse_id_token` always called when OIDC; checks signature, `aud`, `iss`, `exp`, `nonce`
- [ ] State parameter validated by Authlib's session middleware - confirm session middleware is mounted (Starlette `SessionMiddleware`, Flask session)
- [ ] Token storage: refresh tokens encrypted at rest; do not store raw `access_token` in client-readable cookies

## 3. Server: ResourceProtector / BearerTokenValidator

**Red Flags:**
```python
# VULNERABLE - custom validator that does not check scope / token revocation
class MyValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return Token.query.filter_by(access_token=token_string).first()
    def request_invalid(self, request): return False
    def token_revoked(self, token): return False                   # never returns True - revocation broken

# SAFE
class MyValidator(BearerTokenValidator):
    def authenticate_token(self, token_string):
        return Token.query.filter_by(access_token=token_string).first()
    def request_invalid(self, request): return False
    def token_revoked(self, token): return token.revoked_at is not None
```

**Checklist:**
- [ ] `BearerTokenValidator.token_revoked` returns the actual revocation state - default subclasses sometimes leave it stubbed `False`
- [ ] `BearerTokenValidator.request_invalid` checks scopes if endpoint requires specific scope (`@require_oauth("scope_name")`)
- [ ] Token storage: hashed access tokens, not plaintext; lookup by hash, not by full token (mitigates DB read-only leak)
- [ ] Token TTL bounded (1h typical for access; refresh longer with rotation)

## 4. Server: Authorization Code / Implicit Grants

**Red Flags:**
```python
# VULNERABLE - custom AuthorizationCodeGrant.create_authorization_code without binding to client + redirect_uri + PKCE
class CodeGrant(AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "none"]  # "none" = public client; OK only with PKCE
    def save_authorization_code(self, code, request):
        AuthCode(code=code, client_id=request.client.client_id, ...).save()  # missing user/redirect_uri/code_challenge

# VULNERABLE - implicit grant still enabled
# OAuth2 implicit grant deprecated; use authorization-code + PKCE instead
```

**Checklist:**
- [ ] `AuthorizationCodeGrant.save_authorization_code` persists `code_challenge`, `code_challenge_method`, `redirect_uri`, `user_id`, `client_id`, expiry
- [ ] `AuthorizationCodeGrant.query_authorization_code` returns codes only if `not expired and not used`
- [ ] Code consumed atomically (`UPDATE ... WHERE code=? AND used=false RETURNING ...` or DB-level constraint) - prevents double-redeem
- [ ] PKCE required for public clients (`require_oauth_authentication = False` for `none` auth method only with PKCE)
- [ ] Implicit grant disabled (`response_type=token`); use authorization-code with PKCE
- [ ] `redirect_uri` exact-match validation (not prefix-match) on registered URIs

## 5. Server: Token Endpoint Authentication

**Red Flags:**
```python
# VULNERABLE - allowing client_secret_post AND client_secret_basic AND none on same client unconditionally
TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_post", "client_secret_basic", "none"]

# VULNERABLE - private_key_jwt without verifying iss/sub/aud/jti
```

**Checklist:**
- [ ] Confidential clients require `client_secret_basic` or `client_secret_post`; never `none`
- [ ] Public clients use `none` only with PKCE
- [ ] If `private_key_jwt` / `client_secret_jwt` enabled: `iss` and `sub` equal `client_id`; `aud` equals token endpoint URL; `jti` tracked for replay prevention
- [ ] Token endpoint rate-limited; failed-auth metrics monitored

## 6. JOSE Usage (authlib.jose)

For JWT verification specifics see `custom-jwt.md`. Authlib-specific:
- [ ] `jwt.decode(token, keyset, claims_options={...})` - `claims_options` lists required claims with `essential: True`
- [ ] `JsonWebKey.import_key_set(jwks)` cached out-of-band; do not refetch on every request
- [ ] `Cipher` / `JWE` use AEAD (`A256GCM`); not `RSA1_5`

## 7. RFC 7662 Token Introspection / Revocation

**Checklist:**
- [ ] Introspection endpoint requires resource-server authentication (not anonymous - prevents token enumeration)
- [ ] Revocation endpoint silently succeeds for unknown tokens (RFC 7009 §2.2) - prevents token enumeration
- [ ] Both endpoints rate-limited

## References

- Authlib docs: https://docs.authlib.org/
- RFC 6749 (OAuth2), RFC 7636 (PKCE), RFC 7591 (Dynamic Client Registration), RFC 7662 (Introspection), RFC 7009 (Revocation)
- OAuth2 Threat Model: RFC 6819
