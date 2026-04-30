---
name: express-session Security Patterns
description: Cookie flags, store, secret rotation, regenerate on login, fixation, MemoryStore in prod
applies_to:
  - dependency: express-session
version: 1
last_updated: 2026-04-30
---

# express-session Security Patterns

Apply when the project uses `express-session` (or compatible middleware like `cookie-session`).

## 1. Cookie Flags

**Red Flags:**
```js
// VULNERABLE - missing flags
app.use(session({ secret: "..." }));                            // no cookie config; defaults are unsafe in prod

// VULNERABLE - secure: false in production
app.use(session({
  secret: "...",
  cookie: { secure: false, httpOnly: false, sameSite: "none" },
}));

// SAFE
app.use(session({
  name: "sid",                                                  // not the default `connect.sid`
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: true,                                               // HTTPS-only; behind a TLS-terminating proxy, set
                                                                // app.set("trust proxy", 1)
    sameSite: "lax",
    maxAge: 24 * 60 * 60 * 1000,
  },
  store: new RedisStore({ client: redis }),
}));
```

**Checklist:**
- [ ] `cookie.httpOnly: true` (default true on express-session, but verify - other middleware differs)
- [ ] `cookie.secure: true` in production; `app.set("trust proxy", N)` if behind a proxy so secure-cookie check passes
- [ ] `cookie.sameSite: "lax"` minimum; `"strict"` for high-value sessions
- [ ] `cookie.maxAge` bounded (24h-7d typical)
- [ ] Custom `name` (not `connect.sid`) reduces fingerprintability

## 2. Secret

**Checklist:**
- [ ] `secret` is a strong random value (≥32 bytes) from secret manager / env
- [ ] `secret` accepts an array for rotation: `[newSecret, oldSecret]` - signs with first, accepts any
- [ ] Old secret retired after one cookie lifetime

## 3. Store

**Red Flags:**
```js
// VULNERABLE - MemoryStore in production (warns at startup, lost on restart, leaks under multi-process)
app.use(session({ secret: "...", /* no store, defaults to MemoryStore */ }));
```

**Checklist:**
- [ ] Production uses an external store: `connect-redis`, `connect-mongo`, `connect-pg-simple`, etc.
- [ ] Store TTL matches cookie maxAge
- [ ] Store credentials from env / secret manager

## 4. Fixation Prevention

**Red Flags:**
```js
// VULNERABLE - existing session ID retained across login (attacker can pre-set a session ID)
app.post("/login", async (req, res) => {
  if (await verify(req.body)) {
    req.session.userId = userId;
    res.send("ok");
  }
});
```

**Checklist:**
- [ ] On successful login, call `req.session.regenerate(cb)` BEFORE writing user identity to the session - issues a new
      session ID, prevents fixation
- [ ] On logout, call `req.session.destroy(cb)` AND clear the cookie
- [ ] Sensitive role transitions (e.g. assume-admin) regenerate the session

## 5. resave / saveUninitialized

**Checklist:**
- [ ] `resave: false` (don't write back unchanged sessions; reduces races)
- [ ] `saveUninitialized: false` (don't create a session for unauthenticated visits; reduces store bloat and
      tracker-cookie compliance issues)
- [ ] Note: with `saveUninitialized: false`, CSRF tokens that depend on a session need to be initialized on first use,
      not lazily

## 6. proxy / Cookie Domain

**Checklist:**
- [ ] `cookie.domain` not set unless cross-subdomain sessions are required; setting too broad enables session theft
      from other subdomains
- [ ] If subdomain sessions are required, `__Host-` prefix on cookie name + `domain` unset is more restrictive (though
      `__Host-` requires no Domain attribute, so it's mutually exclusive with cross-subdomain)
- [ ] `proxy: true` only when behind a TLS-terminating proxy and `app.set("trust proxy", N)` configured

## 7. Concurrent Sessions

**Checklist:**
- [ ] Application policy on concurrent sessions documented (allow many vs. one-at-a-time)
- [ ] If one-at-a-time: store keeps a `userId -> sessionId` index; new login revokes the old session
- [ ] Session list visible in user account settings; user can revoke individual sessions

## References

- express-session: https://github.com/expressjs/session
- OWASP Session Management Cheat Sheet
