---
name: Passport.js Security Patterns
description: Strategy verification, session serialization, OAuth state, multi-strategy account linking
applies_to:
  - dependency: passport
version: 1
last_updated: 2026-04-30
---

# Passport.js Security Patterns

Apply when the project uses Passport.js. Covers strategy verification, session serialization,
OAuth state handling, and account-linking pitfalls.

## 1. Local Strategy

**Red Flags:**
```js
// VULNERABLE - == comparison on password (also: comparing plaintext, not hash)
passport.use(new LocalStrategy((email, password, done) => {
  User.findOne({ email }, (err, user) => {
    if (user.password === password) return done(null, user);    // plaintext compare
    done(null, false);
  });
}));

// SAFE
passport.use(new LocalStrategy(async (email, password, done) => {
  try {
    const user = await User.findOne({ email });
    if (!user) {
      // run a dummy hash compare to keep timing constant
      await bcrypt.compare(password, "$2b$12$dummyhashtoeqtimestoreinrealhash");
      return done(null, false);
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    return done(null, ok ? user : false);
  } catch (e) { done(e); }
}));
```

**Checklist:**
- [ ] Password compared via `bcrypt.compare` / `argon2.verify` - never `===` or `==`
- [ ] User-not-found path performs a dummy hash compare to flatten timing (prevents user enumeration via login latency)
- [ ] Generic error message on failure (`Invalid credentials`) - never "user not found" vs "wrong password"
- [ ] Rate limiting applied to login route (express-rate-limit or upstream)

## 2. JWT Strategy

**Red Flags:**
```js
// VULNERABLE - jwtFromRequest pulled from query string (logged, leaked in referrers)
new JwtStrategy({ jwtFromRequest: ExtractJwt.fromUrlQueryParameter("token"), secretOrKey });

// VULNERABLE - ignoreExpiration true
new JwtStrategy({ ignoreExpiration: true, secretOrKey, jwtFromRequest });

// VULNERABLE - no algorithms specified
new JwtStrategy({ secretOrKey, jwtFromRequest });               // accepts any alg, including none
```

**Checklist:**
- [ ] `jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken()` for APIs
- [ ] `ignoreExpiration: true` flagged - only acceptable for explicit refresh-token endpoint
- [ ] `algorithms: ['RS256']` (or HS256, but never both with same key)
- [ ] `audience` and `issuer` validated
- [ ] `secretOrKeyProvider` for JWKS / rotation; HTTPS-only fetch; `kid` allowlist

## 3. OAuth / OIDC Strategies

**Red Flags:**
```js
// VULNERABLE - state parameter not used; CSRF on callback
new GoogleStrategy({ clientID, clientSecret, callbackURL });
app.get("/auth/google", passport.authenticate("google"));       // no state
app.get("/auth/google/cb", passport.authenticate("google"));    // attacker forces victim to log in as attacker's google
```

**Checklist:**
- [ ] OAuth strategies use `state: true` (passport-google-oauth20 ≥2.x default) - prevents CSRF on callback
- [ ] PKCE used for public clients / SPAs (`pkce: true`)
- [ ] `callbackURL` matches a registered URL on the IdP; no wildcard registration
- [ ] `scope` minimized - request only what's needed
- [ ] Account linking (signing in with provider X when an account with the same email exists from provider Y) verifies
      email ownership before linking; otherwise pre-existing account hijack
- [ ] Refresh tokens stored encrypted at rest; rotated on use

## 4. Session Serialization

**Red Flags:**
```js
// VULNERABLE - serializing the entire user object into the session cookie
passport.serializeUser((user, done) => done(null, user));       // includes passwordHash, internal fields
passport.deserializeUser((user, done) => done(null, user));     // no DB check; revoked users still authenticated
```

**Checklist:**
- [ ] `serializeUser` stores only the user ID (or session ID), not the full user object
- [ ] `deserializeUser` re-fetches from DB on each request (or uses a cache with bounded TTL) - allows account
      revocation to take effect
- [ ] Session store is server-side (redis, db) for revocation; signed-cookie-only sessions cannot be revoked

## 5. Account Linking / Pre-existing Email

**Red Flags:**
```js
// VULNERABLE - automatic link by email without verification
new GoogleStrategy({ ... }, async (at, rt, profile, done) => {
  let user = await User.findOne({ email: profile.emails[0].value });
  if (!user) user = await User.create({ email: profile.emails[0].value, googleId: profile.id });
  else user.googleId = profile.id;                              // attacker creates Google account with victim's email,
                                                                // takes over victim's existing account
  await user.save();
  done(null, user);
});
```

**Checklist:**
- [ ] Account linking by email requires the email to be marked verified by the IdP (`profile.emails[0].verified`,
      OIDC `email_verified: true`) AND a confirmation step from the user
- [ ] If only IdP-claimed email is available, do not auto-link to existing accounts; create a new account or require
      sign-in with the existing credential first

## 6. Logout / Session Termination

**Checklist:**
- [ ] Logout calls `req.logout()` AND `req.session.destroy()` (Express); cookie cleared
- [ ] Server-side session record deleted (so a stolen session ID cannot be reused after logout)
- [ ] CSRF protection on logout endpoint (don't let attackers force-logout users)

## 7. Multi-Factor

**Checklist:**
- [ ] MFA enrollment requires re-auth (current password / fresh session)
- [ ] TOTP secrets encrypted at rest; backup codes hashed (bcrypt) and single-use
- [ ] Recovery flows (account-recovery email, SMS) audited - they are the weakest link

## References

- Passport: https://www.passportjs.org/
- OAuth state CSRF: https://datatracker.ietf.org/doc/html/rfc6749#section-10.12
