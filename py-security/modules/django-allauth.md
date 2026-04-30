---
name: django-allauth Security Patterns
description: Signup adapters, social-account email-verified linking, account-existence enumeration, MFA, social provider config
applies_to:
  - dependency: django-allauth
version: 1
last_updated: 2026-04-30
---

# django-allauth Security Patterns

Apply when project uses `django-allauth`. Covers configuration knobs that determine whether
account-takeover via social login, account enumeration, or weak signup defaults are exposed.
Pairs with `django.md` (settings hygiene) and `oauth2.md` (provider-side OIDC/OAuth2 details).

## 1. Signup / Registration Defaults

**Red Flags:**
```python
# VULNERABLE - email verification disabled or "optional"; attacker registers with someone else's email
ACCOUNT_EMAIL_VERIFICATION = "none"
ACCOUNT_EMAIL_VERIFICATION = "optional"

# VULNERABLE - public signup with admin-by-default in custom adapter
class MyAdapter(DefaultAccountAdapter):
    def save_user(self, request, user, form, commit=True):
        user.is_staff = True                                       # never grant elevated role on public signup
        return super().save_user(request, user, form, commit)

# SAFE
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
ACCOUNT_LOGIN_ATTEMPTS_LIMIT = 5                                   # default; tune to threat model
ACCOUNT_LOGIN_ATTEMPTS_TIMEOUT = 300
ACCOUNT_RATE_LIMITS = {                                            # allauth ≥0.55
    "login_failed": "5/5m/ip,5/5m/user",
    "signup": "20/m/ip",
    "send_email": "5/5m",
    "reset_password": "5/5m/ip,5/5m/key",
    "reset_password_email": "5/5m",
    "confirm_email": "1/3m/key",
}
```

**Checklist:**
- [ ] `ACCOUNT_EMAIL_VERIFICATION = "mandatory"` (not `"none"` / `"optional"`) for any application that grants resources based on email
- [ ] `ACCOUNT_RATE_LIMITS` set; defaults exist but are easy to disable globally - confirm not overridden to `None`
- [ ] Custom `DefaultAccountAdapter.save_user` does not assign `is_staff`, `is_superuser`, group memberships, or tenant from the signup form
- [ ] `ACCOUNT_USERNAME_REQUIRED` / `ACCOUNT_AUTHENTICATION_METHOD` matches model expectations (mismatch can let attackers register without setting required fields)
- [ ] `ACCOUNT_USER_MODEL_USERNAME_FIELD = None` if email-only login (avoids username collisions / squatting)
- [ ] Signup form validation includes password length and complexity (Django `AUTH_PASSWORD_VALIDATORS`)

## 2. Social-Account Auto-Linking (the takeover footgun)

**Red Flags:**
```python
# VULNERABLE - ACCOUNT_UNIQUE_EMAIL True + auto-linking on email match without IdP verification
SOCIALACCOUNT_EMAIL_VERIFICATION = "none"                          # trust IdP-claimed email blindly
SOCIALACCOUNT_AUTO_SIGNUP = True

# Custom adapter that links by email without checking verified flag:
class SocAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        if sociallogin.is_existing: return
        try:
            existing = User.objects.get(email=sociallogin.user.email)
            sociallogin.connect(request, existing)                 # attacker creates IdP account with victim's email,
                                                                   # logs in, takes over victim's existing account
        except User.DoesNotExist: pass

# SAFE - require IdP-verified email AND known-trusted IdP before auto-link
class SocAdapter(DefaultSocialAccountAdapter):
    TRUSTED_IDPS = {"google", "microsoft"}                         # IdPs that actually verify email
    def pre_social_login(self, request, sociallogin):
        if sociallogin.is_existing: return
        email = sociallogin.account.extra_data.get("email")
        verified = sociallogin.account.extra_data.get("email_verified") is True
        if not (email and verified and sociallogin.account.provider in self.TRUSTED_IDPS): return
        try:
            existing = User.objects.get(email__iexact=email)
        except User.DoesNotExist: return
        if not existing.emailaddress_set.filter(email__iexact=email, verified=True).exists(): return
        sociallogin.connect(request, existing)
```

**Attack Scenario:** attacker registers Google account with victim's email (Google enforces verification, but other IdPs may not); allauth links to existing local account on first login; attacker now holds the account.

**Checklist:**
- [ ] `SOCIALACCOUNT_EMAIL_VERIFICATION = "mandatory"` OR custom `pre_social_login` checks `email_verified` claim AND restricts to IdPs known to verify
- [ ] Custom social adapter `pre_social_login` does NOT auto-connect existing accounts solely by email match
- [ ] Account-linking flow requires the user to be authenticated to the existing account (post-login link, not pre-login)
- [ ] `SOCIALACCOUNT_AUTO_SIGNUP = False` if your model requires extra fields not provided by IdP
- [ ] Per-provider `EMAIL_AUTHENTICATION` / `VERIFIED_EMAIL` settings reviewed for each enabled provider

## 3. Account Existence Enumeration

**Red Flags:**
```python
# VULNERABLE - login error tells attacker if account exists
"Account does not exist"      # vs.
"Wrong password"

# VULNERABLE - signup says "email already taken" -> enumerates accounts
ACCOUNT_PREVENT_ENUMERATION = False                                # DEPRECATED in newer versions; default is now True
```

**Checklist:**
- [ ] `ACCOUNT_PREVENT_ENUMERATION = True` (default in current versions; verify not overridden)
- [ ] Password-reset endpoint always returns the same response shape regardless of whether the account exists ("If an account exists, an email has been sent")
- [ ] Signup with an already-registered email triggers a notice email to the existing account, not a UI error revealing existence
- [ ] Rate-limit `reset_password_email` and `signup` per IP and per email key (`ACCOUNT_RATE_LIMITS`)
- [ ] Login error messages generic; same status code on bad-password vs unknown-email vs locked-account

## 4. Email Confirmation Token Lifetime

**Red Flags:**
```python
# VULNERABLE - confirmation never expires or expires far in the future; reused links survive password resets
ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS = 365
```

**Checklist:**
- [ ] `ACCOUNT_EMAIL_CONFIRMATION_EXPIRE_DAYS` ≤ 3 (default is 3; do not raise to weeks/months)
- [ ] Confirmation tokens single-use - allauth marks `EmailConfirmation.sent` and consumes on confirm; verify custom flows do not reuse
- [ ] Password-reset tokens use Django's signed token with short TTL; allauth wraps Django's default - do not weaken

## 5. Multi-Factor (allauth-mfa)

**Checklist:**
- [ ] `allauth.mfa` enabled if MFA is offered; backed by `django-otp` or built-in TOTP - check version
- [ ] TOTP secrets encrypted at rest; recovery codes hashed (Argon2/bcrypt) and single-use
- [ ] MFA enrollment requires fresh authentication (`ACCOUNT_REAUTHENTICATION_REQUIRED = True` for sensitive endpoints)
- [ ] Fallback / recovery flows audited - they are the weakest link

## 6. Logout / Session Termination

**Checklist:**
- [ ] `ACCOUNT_LOGOUT_ON_GET = False` (default) - prevents CSRF-triggered logout via image tags
- [ ] `ACCOUNT_LOGOUT_REDIRECT_URL` is a relative path or pinned host
- [ ] Server-side session record deleted on logout (Django default with `db` session backend)

## 7. Provider-Specific

**Checklist:**
- [ ] Each provider's client secret in env / secret manager, not `SOCIALACCOUNT_PROVIDERS` literal in settings
- [ ] OAuth2 providers use PKCE where supported (allauth ≥0.50 supports PKCE for many providers; verify per-provider config)
- [ ] OIDC providers: `nonce` enabled; `id_token` verified (allauth handles by default - check for custom overrides)
- [ ] SAML provider config (`allauth.socialaccount.providers.saml`) - see `saml.md` for XSW / metadata SSRF
- [ ] Apple Sign-In requires `client_secret` JWT signed with the team's private key - rotated; key not committed

## References

- django-allauth docs: https://docs.allauth.org/
- Account-takeover via social login: https://www.descope.com/blog/post/noauth
- OWASP ASVS V2 (Authentication)
