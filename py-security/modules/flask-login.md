---
name: Flask-Login Security Patterns
description: User loader, fresh-login, remember-me cookie, session protection, anonymous user, logout
applies_to:
  - dependency: flask-login
version: 1
last_updated: 2026-04-30
---

# Flask-Login Security Patterns

Apply when project uses `flask-login`. Covers session-cookie auth, remember-me tokens, fresh-
login gating, and the user loader. For underlying Flask session details (`SECRET_KEY`,
signed-cookie session) see `flask.md`. For password hashing, JWT, OAuth - see SKILL.md and
the relevant module.

## 1. User Loader

**Red Flags:**
```python
# VULNERABLE - user_loader returns user from a single ID without checking active/banned
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))                            # banned users still authenticated
                                                                   # no fresh check; revocation impossible until session expires

# VULNERABLE - user_loader trusts attacker-controlled user_id format (e.g. tenant in id)
@login_manager.user_loader
def load_user(user_id):
    tenant, uid = user_id.split(":")                               # tampered cookie may swap tenant
    return User.query.filter_by(id=uid, tenant=tenant).first()
```

**Checklist:**
- [ ] `user_loader` checks user state (active, not banned, not deleted) on every request - or session expiry is short enough that revocation lag is acceptable
- [ ] User ID parsed strictly (`int(user_id)`); composite IDs avoided - tenant scope read from server-side session, not the user_id string
- [ ] `request_loader` (token-based) used only for stateless API; verifies HMAC / JWT properly (see `custom-jwt.md`)
- [ ] Per-request DB hit acceptable; if cached, cache invalidated on user state changes (password reset, ban, role change)

## 2. Remember-Me Cookie

**Red Flags:**
```python
# VULNERABLE - remember-me default lifetime is 1 year; theft = persistent access
login_user(user, remember=True)

# VULNERABLE - REMEMBER_COOKIE_HTTPONLY / SECURE / SAMESITE not set
app.config["REMEMBER_COOKIE_HTTPONLY"] = False
app.config["REMEMBER_COOKIE_SECURE"] = False                       # cookie sent over plain HTTP
app.config["REMEMBER_COOKIE_SAMESITE"] = None
```

**Checklist:**
- [ ] `REMEMBER_COOKIE_DURATION` bounded (≤30 days typical; days, not years)
- [ ] `REMEMBER_COOKIE_HTTPONLY = True` (default; verify not overridden)
- [ ] `REMEMBER_COOKIE_SECURE = True` in production
- [ ] `REMEMBER_COOKIE_SAMESITE = "Lax"` (or `"Strict"` for high-value)
- [ ] Token stored is `User.get_auth_token()` (default uses `User.get_id()` + `User.password` salt; mutate `User.password` to invalidate all remember-me tokens after a security event)
- [ ] On logout, `REMEMBER_COOKIE_NAME` deleted (`logout_user()` handles, but custom logout endpoints must call it)
- [ ] Remember-me login marks `current_user.is_authenticated = True` but `current_user.is_fresh = False` - sensitive endpoints check `fresh_login_required`

## 3. Fresh-Login Gating

**Red Flags:**
```python
# VULNERABLE - sensitive endpoint accepts remember-me-resumed sessions
@app.route("/account/email", methods=["POST"])
@login_required
def change_email():
    current_user.email = request.form["email"]
    db.session.commit()                                            # remember-me token theft -> email change -> account takeover
```

**Checklist:**
- [ ] Sensitive endpoints (password change, email change, MFA enrollment, payment method, API key creation) decorated with `fresh_login_required` - forces re-auth if session was resumed via remember-me
- [ ] `REFRESH_VIEW` configured to a re-authentication form
- [ ] `REMEMBER_SEEN_VIEW` (Flask-Login ≥0.6) reviewed if used for additional gating

## 4. Session Protection

**Red Flags:**
```python
# VULNERABLE - SESSION_PROTECTION = None (disables IP+UA hashing for remember-me sessions)
app.config["SESSION_PROTECTION"] = None
```

**Checklist:**
- [ ] `SESSION_PROTECTION = "strong"` for high-value apps (regenerates session on remote-addr / user-agent change; aggressive but effective)
- [ ] `SESSION_PROTECTION = "basic"` minimum (marks session non-fresh on change, requires re-auth for `fresh_login_required`)
- [ ] Note: `"strong"` may cause false logouts behind load balancers that vary client IP - test before enabling

## 5. Login / Logout

**Red Flags:**
```python
# VULNERABLE - login_user without password verification (logic error)
user = User.query.filter_by(email=email).first()
login_user(user)                                                   # no bcrypt.check_password_hash before this

# VULNERABLE - logout endpoint accepts GET (CSRF-triggered logout via image tag)
@app.route("/logout")
def logout():
    logout_user()
    return redirect("/")
```

**Checklist:**
- [ ] `login_user(user)` only after password verification with `bcrypt`/`argon2` (constant-time)
- [ ] User-not-found path performs a dummy hash compare to flatten timing (prevents user enumeration via login latency)
- [ ] Login endpoint generic error: "Invalid credentials"; not "user not found" vs "wrong password"
- [ ] Login route rate-limited (`flask-limiter` or upstream); per-IP and per-account
- [ ] Session regenerated on login (`session.regenerate()` if using `flask-session`; default Flask signed cookie effectively rotates because session id is the cookie content)
- [ ] Logout endpoint requires POST (CSRF token) or has CSRF protection on GET; calls `logout_user()` AND clears `session.clear()` if extra data stored

## 6. Anonymous User

**Red Flags:**
```python
# VULNERABLE - custom AnonymousUserMixin grants permissions
class Anon(AnonymousUserMixin):
    @property
    def is_authenticated(self): return True                        # never lie here

login_manager.anonymous_user = Anon
```

**Checklist:**
- [ ] Custom `AnonymousUserMixin` does NOT report `is_authenticated = True`
- [ ] Permission checks (`current_user.has_role(...)`) explicit; do not assume "logged in" without `current_user.is_authenticated`

## 7. Multi-Tenant / Authorization Layer

**Checklist:**
- [ ] `current_user` only carries identity; tenant / role enforcement is at the query / view layer
- [ ] `@login_required` is necessary but not sufficient - every protected view also checks resource ownership / tenant scope (see SKILL.md A01)
- [ ] Sensitive views also check `current_user.is_active` (banned-after-login covered if session is short)

## 8. Token Login (request_loader)

**Checklist:**
- [ ] If `request_loader` used (API tokens / signed-token magic links), token verification is constant-time (`hmac.compare_digest`) and includes expiry
- [ ] Token storage uses hashed values, not plaintext
- [ ] Token revocation list checked or expiry is short

## References

- Flask-Login docs: https://flask-login.readthedocs.io/
- OWASP Session Management Cheat Sheet
