---
name: Django Security Patterns
description: Django settings hygiene, CSRF, ORM raw queries, middleware order, admin exposure
applies_to:
  - framework: django
  - dependency: django
version: 1
last_updated: 2026-04-29
---

# Django Security Patterns

Apply when the project uses Django (any version). For Django REST Framework, also load `drf.md`. For multi-tenant Django, also load `multitenancy.md`.

## 1. Settings Hygiene

**Red Flags:**
```python
# settings.py - VULNERABLE
DEBUG = True                              # in production
SECRET_KEY = "django-insecure-..."        # the literal default startproject value
ALLOWED_HOSTS = ["*"]                     # accepts any Host header
CSRF_TRUSTED_ORIGINS = ["*"]              # defeats CSRF origin pinning
SESSION_COOKIE_SECURE = False             # session cookie sent over HTTP
CSRF_COOKIE_SECURE = False
SECURE_SSL_REDIRECT = False               # HTTP requests served as-is
SECURE_HSTS_SECONDS = 0                   # no HSTS

# SAFE
DEBUG = False
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]   # from secret store, ≥50 chars
ALLOWED_HOSTS = ["app.example.com"]
CSRF_TRUSTED_ORIGINS = ["https://app.example.com"]
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
SECURE_REFERRER_POLICY = "same-origin"
```

**Checklist:**
- [ ] `DEBUG = False` in production (verify via deploy config, not just default)
- [ ] `SECRET_KEY` from environment / secret manager, not committed; not the `django-insecure-` default
- [ ] `ALLOWED_HOSTS` is an explicit list, no `"*"`
- [ ] `CSRF_TRUSTED_ORIGINS` lists exact `https://...` origins; no scheme-less or wildcard
- [ ] `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY` all `True`
- [ ] `SESSION_COOKIE_SAMESITE` set (`"Lax"` or `"Strict"`)
- [ ] `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS ≥ 31536000`, `SECURE_HSTS_INCLUDE_SUBDOMAINS = True`
- [ ] `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS = "DENY"` (or per-view)
- [ ] Run `python manage.py check --deploy` and address all warnings

## 2. ORM Raw Queries

**Red Flags:**
```python
# VULNERABLE
User.objects.raw(f"SELECT * FROM auth_user WHERE email = '{email}'")
User.objects.extra(where=[f"email = '{email}'"])
connection.cursor().execute(f"SELECT * FROM x WHERE y = '{val}'")

# SAFE
User.objects.raw("SELECT * FROM auth_user WHERE email = %s", [email])
User.objects.filter(email=email)             # use the ORM
with connection.cursor() as c:
    c.execute("SELECT * FROM x WHERE y = %s", [val])
```

**Checklist:**
- [ ] Grep for `.raw(`, `.extra(`, `cursor().execute(` near f-string / `%`/ `.format(`
- [ ] No string interpolation into `.raw()` SQL
- [ ] No `.extra(where=...)` with user input
- [ ] Dynamic table/column names validated against an allowlist before use

## 3. CSRF

**Red Flags:**
```python
# VULNERABLE - blanket exemption on a state-changing view
@csrf_exempt
def update_profile(request): ...

# VULNERABLE - exempted because "we use tokens" but session cookie still authenticates
@csrf_exempt
@login_required
def transfer_funds(request): ...
```

**Checklist:**
- [ ] `@csrf_exempt` only on stateless API endpoints that authenticate via header (Bearer token), not session cookie
- [ ] `CsrfViewMiddleware` enabled in `MIDDLEWARE`
- [ ] AJAX requests include `X-CSRFToken` header from `csrftoken` cookie
- [ ] `CSRF_COOKIE_HTTPONLY` is `False` *only* if JS reads it (Django pattern); pair with `SameSite=Lax` and `Secure`

## 4. Authentication & Sessions

**Checklist:**
- [ ] Custom `AUTH_PASSWORD_VALIDATORS` configured (Django defaults are minimal)
- [ ] Default `PBKDF2PasswordHasher` retained or upgraded to `Argon2PasswordHasher` (install `argon2-cffi`)
- [ ] `login()` called after authentication regenerates the session key (Django does this; verify custom auth backends preserve it)
- [ ] Password reset uses the built-in `PasswordResetView` (single-use tokens) or equivalent; not hand-rolled
- [ ] `SESSION_EXPIRE_AT_BROWSER_CLOSE = True` for sensitive applications
- [ ] `SESSION_COOKIE_AGE` and absolute session timeout enforced (Django defaults: rolling 2 weeks)

## 5. Templates

**Red Flags:**
```python
# VULNERABLE - mark_safe with user input
from django.utils.safestring import mark_safe
return mark_safe(f"<p>{user_bio}</p>")

# VULNERABLE - {% autoescape off %} block with user data inside

# SAFE
from django.utils.html import format_html
return format_html("<p>{}</p>", user_bio)
```

**Checklist:**
- [ ] Grep for `mark_safe(`, `| safe`, `{% autoescape off %}` — each occurrence justified
- [ ] `format_html` used instead of `mark_safe(f"...")`
- [ ] Custom template tags returning HTML use `format_html`, not string concat
- [ ] No user input rendered inside `<script>` or `<style>` tags (XSS via template even with autoescape; use `json_script`)

## 6. Admin Exposure

**Checklist:**
- [ ] `/admin` not exposed on the public domain, OR
- [ ] `/admin` IP-allowlisted at the proxy, OR
- [ ] `/admin` behind a non-default URL path (defense in depth, not primary control)
- [ ] Superuser MFA enforced (e.g. `django-otp`, `django-allauth-mfa`)
- [ ] `ModelAdmin.has_delete_permission` reviewed for soft-delete vs hard-delete semantics
- [ ] `ModelAdmin.list_display` does not leak hashed passwords / tokens / secrets

## 7. File Uploads & Media

See `file-upload.md`. Django-specific:
- [ ] `MEDIA_ROOT` outside the webroot OR served through an authenticated view
- [ ] `FileField` / `ImageField` `upload_to` is a callable that sanitizes the filename
- [ ] `DEFAULT_FILE_STORAGE` set to a secure backend (S3 with signed URLs, not public bucket)

## 8. Middleware Order

Order matters. Common mistakes:
- `SecurityMiddleware` listed after middleware that returns early (HSTS / SSL redirect skipped)
- `CsrfViewMiddleware` after `AuthenticationMiddleware` is fine; but custom auth that bypasses CSRF must run *after* CSRF
- `XFrameOptionsMiddleware` missing entirely

**Checklist:**
- [ ] `SecurityMiddleware` first in the list
- [ ] `SessionMiddleware` before `CsrfViewMiddleware` before `AuthenticationMiddleware`
- [ ] `XFrameOptionsMiddleware` present
- [ ] No custom middleware bypasses CSRF or auth based on user-controlled headers

## References

- Django security docs: https://docs.djangoproject.com/en/stable/topics/security/
- `python manage.py check --deploy`
- OWASP Django Security Cheat Sheet
