---
name: Flask Security Patterns
description: SECRET_KEY, signed-cookie sessions, render_template_string, blueprint auth gaps, send_file traversal
applies_to:
  - framework: flask
  - dependency: flask
version: 1
last_updated: 2026-04-29
---

# Flask Security Patterns

Apply when the project uses Flask. Quart shares most of these (async variant). Flask-RESTful, Flask-Smorest, Flask-Login
concerns covered inline.

## 1. SECRET_KEY and Session Integrity

Flask sessions are *signed*, not encrypted, by default — any client can read session contents. Forgery is the threat
model, not confidentiality.

**Red Flags:**
```python
# VULNERABLE - default / committed / weak key
app.secret_key = "dev"
app.config["SECRET_KEY"] = "change-me"

# VULNERABLE - session stores secrets the client should not see
session["password_reset_token"] = token   # client sees it (signed but not encrypted)
session["internal_user_role"] = "admin"   # tamper-detected, but readable

# SAFE
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]   # ≥32 random bytes
```

**Checklist:**
- [ ] `SECRET_KEY` from environment, ≥32 bytes of entropy, not committed
- [ ] Key rotation supported (`SECRET_KEY_FALLBACKS` in Flask 3.0+; for earlier versions use server-side sessions)
- [ ] Sensitive values not stored in client-side session (use `flask-session` with Redis/DB backend if you need to)
- [ ] `SESSION_COOKIE_SECURE = True`, `SESSION_COOKIE_HTTPONLY = True`, `SESSION_COOKIE_SAMESITE = "Lax"`
- [ ] `PERMANENT_SESSION_LIFETIME` set explicitly; don't rely on default

## 2. Template Injection (SSTI)

See SKILL.md "SSTI" for the core pattern. Flask-specific:

**Red Flags:**
```python
# VULNERABLE - render_template_string with user input as the template body
return render_template_string(f"Hello {request.args['name']}")
# attacker: ?name={{config}} -> leaks SECRET_KEY
# attacker: ?name={{ ''.__class__.__mro__[1].__subclasses__() }} -> RCE chain

# SAFE
return render_template_string("Hello {{ name }}", name=request.args["name"])
```

**Checklist:**
- [ ] Grep `render_template_string` — every call's first arg is a static string, not f-string with request data
- [ ] User-authored templates (CMS / email templates feature) use `jinja2.SandboxedEnvironment` AND assume sandbox
      bypass exists
- [ ] `app.jinja_env.autoescape` is True (Flask default; verify not disabled)

## 3. Blueprint Auth Gaps

**Red Flags:**
```python
# VULNERABLE - decorator order: route registered before login check
@bp.route("/secret")
@login_required           # runs after route registration but - if forgotten on a sister view, that view is open
def secret(): ...

# VULNERABLE - blueprint-level before_request check skipped on a public sister view that should be auth'd
@bp.before_request
def require_login():
    if request.endpoint == "public_endpoint":
        return None
    if not current_user.is_authenticated:
        abort(401)
```

**Checklist:**
- [ ] Auth applied via `before_request` on the blueprint (centralized) OR via decorator on every route — pick one and
      audit consistency
- [ ] No `if request.endpoint == "..."` skip-list patterns; whitelist what's public, deny by default
- [ ] Flask-Login `login_required` decorator on every protected view; consider `@bp.before_request` enforcement to avoid
      omissions
- [ ] Role checks (admin, owner) done in a dedicated decorator, not inline; easier to audit
- [ ] `current_user.is_authenticated` is the *only* signal trusted (not session keys, not cookies you set)

## 4. send_file / send_from_directory — Path Traversal

**Red Flags:**
```python
# VULNERABLE
@app.route("/download/<path:fname>")
def download(fname):
    return send_file(os.path.join(UPLOADS, fname))   # ../../etc/passwd

# SAFE
@app.route("/download/<path:fname>")
def download(fname):
    return send_from_directory(UPLOADS, fname)       # built-in safe_join
```

**Checklist:**
- [ ] `send_file` not used with user-controlled paths; prefer `send_from_directory`
- [ ] If `send_file` is required, path resolved and verified under base (see SKILL.md "Path Traversal")
- [ ] Static file serving in production handled by reverse proxy, not Flask

## 5. JSON / Form Body Caps

**Checklist:**
- [ ] `MAX_CONTENT_LENGTH` set globally (Flask does not cap by default)
- [ ] Pre-auth endpoints have tighter caps via reverse proxy
- [ ] `request.get_json(silent=True)` to avoid 500s on malformed JSON, but validate the result before use

## 6. CSRF

Flask itself ships no CSRF protection. Use Flask-WTF (`CSRFProtect`) or roll equivalent.

**Checklist:**
- [ ] `CSRFProtect(app)` enabled OR token-based auth on all state-changing endpoints
- [ ] AJAX endpoints either include CSRF token in header OR authenticate via `Authorization: Bearer ...` (no cookie
      auth)
- [ ] WTForms `validate_on_submit()` used for form submissions (includes CSRF check)

## 7. Debug Mode and the Werkzeug Console

**Red Flags:**
```python
# VULNERABLE - the Werkzeug debugger console = RCE for anyone who reaches the page
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
```

**Checklist:**
- [ ] `debug=True` only when `host` is `127.0.0.1`; never on a publicly bound port
- [ ] `FLASK_DEBUG=0` / `FLASK_ENV=production` in production
- [ ] If debug accidentally exposed, `WERKZEUG_DEBUG_PIN` is generated each restart but the console is RCE — treat as
      compromise

## 8. Cookies and Headers

**Checklist:**
- [ ] `flask-talisman` (or equivalent) configured for HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- [ ] Custom `set_cookie` calls include `secure=True`, `httponly=True`, `samesite="Lax"`
- [ ] `app.config["PREFERRED_URL_SCHEME"] = "https"` set when behind a proxy (affects `url_for(_external=True)`)

## References

- Flask security: https://flask.palletsprojects.com/en/stable/web-security/
- Flask-WTF CSRF: https://flask-wtf.readthedocs.io/en/stable/csrf/
- flask-talisman: https://github.com/GoogleCloudPlatform/flask-talisman
