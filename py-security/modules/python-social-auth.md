---
name: python-social-auth Security Patterns
description: Pipeline ordering, association vs disconnection, partial pipeline tampering, social-link account takeover
applies_to:
  - dependency: social-auth-app-django
  - dependency: social-auth-app-flask
  - dependency: social-auth-core
version: 1
last_updated: 2026-04-30
---

# python-social-auth Security Patterns

Apply when project uses `social-auth-core` (with django/flask/pyramid bindings). The library
chains user lookup, association, account creation, and login through a configurable
**pipeline**; pipeline order and step inclusion are where most takeover bugs hide.

## 1. Pipeline Ordering

**Red Flags:**
```python
# VULNERABLE - associate_by_email BEFORE require_email; existing accounts get linked
# without confirming the IdP-provided email is verified
SOCIAL_AUTH_PIPELINE = (
    "social_core.pipeline.social_auth.social_details",
    "social_core.pipeline.social_auth.social_uid",
    "social_core.pipeline.social_auth.auth_allowed",
    "social_core.pipeline.social_auth.social_user",
    "social_core.pipeline.social_auth.associate_by_email",         # links to existing account by email match
    "social_core.pipeline.user.get_username",
    "social_core.pipeline.user.create_user",
    "social_core.pipeline.social_auth.associate_user",
    "social_core.pipeline.social_auth.load_extra_data",
    "social_core.pipeline.user.user_details",
)

# VULNERABLE - missing partial / mail_validation steps when require_email is on
# pipeline gets stuck mid-flow; tampering with partial token can skip steps

# SAFE - either omit associate_by_email entirely, or add a custom step that
# checks email_verified and provider trust before connecting
SOCIAL_AUTH_PIPELINE = (
    "social_core.pipeline.social_auth.social_details",
    "social_core.pipeline.social_auth.social_uid",
    "social_core.pipeline.social_auth.auth_allowed",
    "social_core.pipeline.social_auth.social_user",
    "myapp.pipeline.require_verified_email",                        # custom: assert email_verified=True
    "myapp.pipeline.associate_by_verified_email",                   # custom: only link if existing.email is verified
    "social_core.pipeline.user.get_username",
    "social_core.pipeline.mail.mail_validation",                    # confirm via emailed link before account creation
    "social_core.pipeline.user.create_user",
    "social_core.pipeline.social_auth.associate_user",
    "social_core.pipeline.social_auth.load_extra_data",
    "social_core.pipeline.user.user_details",
)
```

**Attack Scenario:** attacker registers an OAuth account at a low-trust IdP (one that does not verify email) using victim's email; pipeline includes `associate_by_email` early; attacker is logged in as victim's existing account.

**Checklist:**
- [ ] `associate_by_email` either removed OR replaced with a custom step that requires `email_verified` from IdP AND restricts to a trusted-IdP allowlist (Google, Microsoft 365, GitHub for verified emails only)
- [ ] `mail_validation` included if `SOCIAL_AUTH_<PROVIDER>_FORCE_EMAIL_VALIDATION = True`; otherwise unverified-email signups slip through
- [ ] Pipeline order does not place account-creation before email validation when validation is required
- [ ] `partial` token (returned to user mid-pipeline) signed and short-lived; attacker cannot resume someone else's partial flow

## 2. Required Settings

**Red Flags:**
```python
# VULNERABLE - missing whitelists allow any domain / email
SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = []                 # empty = allow all
SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = []

# VULNERABLE - SECRET_KEY reuse for state token signing without rotation
# python-social-auth signs state with Django SECRET_KEY; if SECRET_KEY rotates without
# SECRET_KEY_FALLBACKS support, in-flight flows break (and may degrade error handling)
```

**Checklist:**
- [ ] Each provider's `KEY` and `SECRET` from env / secret manager; not in `settings.py` / VCS
- [ ] `SOCIAL_AUTH_REDIRECT_IS_HTTPS = True` (or set `SOCIAL_AUTH_<PROVIDER>_REDIRECT_URI` explicitly to HTTPS)
- [ ] `SOCIAL_AUTH_LOGIN_REDIRECT_URL` is a relative path or pinned host
- [ ] Per-provider extra scopes minimized (`SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE = ["email", "profile"]`)
- [ ] `SOCIAL_AUTH_RAISE_EXCEPTIONS = False` in production (default) - tracebacks would otherwise reveal pipeline state

## 3. Disconnect / Unlink

**Red Flags:**
```python
# VULNERABLE - allow disconnecting the last auth method (user locked out, or worse:
# attacker disconnects victim's social account so victim cannot recover)
SOCIAL_AUTH_PROTECTED_USER_FIELDS = []
```

**Checklist:**
- [ ] `disconnect` view requires the user to have an alternative auth method (password set, another social account)
- [ ] `SOCIAL_AUTH_PROTECTED_USER_FIELDS` lists fields not to be overwritten by social provider on subsequent logins (`["email", "is_staff", "is_superuser"]`)
- [ ] Disconnect emits an audit log entry; user notified by email

## 4. State / CSRF

**Checklist:**
- [ ] Default state validation enabled - `SOCIAL_AUTH_<PROVIDER>_STATE_PARAMETER` not set to `False`
- [ ] Session middleware mounted before social-auth views (state stored in session)
- [ ] OAuth1 providers (Twitter pre-2023, etc.) - request-token swap audited; storage of intermediate token secure

## 5. ID Token / Userinfo Validation (OIDC providers)

**Checklist:**
- [ ] OIDC providers use `social_core.backends.oauth.OAuth2.OPENID_CONFIGURATION_URL` if available; signature verified
- [ ] `nonce` enabled (default for built-in OIDC backends; verify custom backends)
- [ ] `email_verified` claim consumed by custom pipeline step before any account linking
- [ ] `aud` matches the application's `client_id`

## 6. Storage

**Checklist:**
- [ ] `UserSocialAuth` table has unique `(provider, uid)` constraint - default; verify migrations applied
- [ ] `extra_data` (JSON) does not store long-lived credentials in plaintext - encrypt at rest if it includes refresh tokens
- [ ] Refresh-token rotation handled via `refresh_token` pipeline step or background job; revoked tokens removed

## 7. Multi-Backend Account Linking

**Red Flags:**
```python
# VULNERABLE - chaining multiple backends without re-auth between linkings
# user logs in via Google, then "connect Twitter" without password / re-auth -
# session compromise allows linking attacker-controlled Twitter to victim account
```

**Checklist:**
- [ ] Connect-additional-provider flow requires re-authentication (recent password / fresh session check)
- [ ] User notified by email when a new auth method is associated with their account

## References

- python-social-auth docs: https://python-social-auth.readthedocs.io/
- Pipeline customization: https://python-social-auth.readthedocs.io/en/latest/pipeline.html
- Account-takeover via social linking: https://www.descope.com/blog/post/noauth
