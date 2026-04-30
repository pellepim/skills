---
name: NextAuth.js / Auth.js Security Patterns
description: Provider config, session strategy, callbacks (signIn/jwt/session), CSRF, trustHost
applies_to:
  - dependency: next-auth
  - dependency: "@auth/core"
version: 1
last_updated: 2026-04-30
---

# NextAuth.js / Auth.js Security Patterns

Apply when the project uses NextAuth.js (v4) or Auth.js (v5).

## 1. NEXTAUTH_SECRET / Session Strategy

**Red Flags:**
```js
// VULNERABLE - missing NEXTAUTH_SECRET in production lets default insecure value through
// (NextAuth v4 generates one in dev; v5 errors at runtime if missing)

// VULNERABLE - session: { strategy: 'jwt' } without rotation/short maxAge
session: { strategy: "jwt", maxAge: 30 * 24 * 60 * 60 }         // 30 days, no rotation
```

**Checklist:**
- [ ] `NEXTAUTH_SECRET` (v4) / `AUTH_SECRET` (v5) set in production from a secret manager; ≥32 bytes random
- [ ] `session.strategy` matches use case: `"database"` for revocation support, `"jwt"` for stateless
- [ ] JWT sessions: `maxAge` bounded (24h-7d typical); `updateAge` triggers rotation
- [ ] Database sessions: enable for high-value apps so logout/revocation actually invalidates server-side

## 2. trustHost / URL Handling

**Red Flags:**
```js
// VULNERABLE - trustHost: true in v5 with no NEXTAUTH_URL allows host header injection
// to redirect callback URLs through attacker-controlled host
{ trustHost: true }                                             // OK behind a proxy you control; risky in serverless without
                                                                // explicit URL pinning
```

**Checklist:**
- [ ] `NEXTAUTH_URL` (v4) / `AUTH_URL` (v5) set to the canonical production URL
- [ ] `trustHost: true` only when the deployment is strictly behind a proxy that strips/rewrites host headers
- [ ] Callback URLs in OAuth provider configs are explicit, not wildcarded

## 3. Callbacks (signIn / jwt / session)

**Red Flags:**
```ts
// VULNERABLE - signIn callback returns true unconditionally (no email-verification check, no allowlist)
async signIn({ user, account, profile }) { return true; }

// VULNERABLE - jwt callback exposes sensitive provider fields to client
async jwt({ token, account, profile }) {
  if (account) token.idToken = account.id_token;                // ID token contains scopes, claims; serialized to client cookie
  return token;
}

// VULNERABLE - session callback exposes role/admin from JWT without verification
async session({ session, token }) {
  session.user.role = token.role;                               // if `token.role` is user-settable, this is privilege escalation
  return session;
}
```

**Checklist:**
- [ ] `signIn` callback enforces email verification (where supported by provider) and any allowlists / domain
      restrictions
- [ ] `jwt` callback does not embed access tokens or ID tokens in the cookie if not needed; if it must, the cookie
      is `httpOnly` (default for NextAuth)
- [ ] `session` callback only exposes fields that the server has authoritative knowledge of; never trust a JWT field
      that originated from user-editable provider profile data
- [ ] `redirect` callback validates redirect targets are same-origin; default behavior allows same-origin only - do not
      override to `return url` blindly

## 4. Account Linking

**Checklist:**
- [ ] `account` table has unique `(provider, providerAccountId)` constraint
- [ ] If linking accounts by email, require email verification on the new provider AND user-confirmed link step
- [ ] Default NextAuth behavior: refuses linking by email if accounts exist; do not override unless aware of the risk

## 5. Credentials Provider

**Red Flags:**
```ts
// VULNERABLE - authorize() returns user without password check
authorize: async (creds) => {
  return await User.findOne({ email: creds.email });            // no bcrypt.compare!
}

// VULNERABLE - generic catch swallows specific errors; user enumeration still possible via timing
```

**Checklist:**
- [ ] `authorize` performs bcrypt/argon2 verify on the password
- [ ] Constant-time behavior on user-not-found (dummy compare) - prevents enumeration
- [ ] Rate limiting on the credentials login route (NextAuth itself does not rate-limit)
- [ ] CSRF: NextAuth uses double-submit token by default; verify it is not disabled

## 6. Adapter Configuration

**Checklist:**
- [ ] Database adapter (Prisma / Drizzle / mongoose) connection string from env, not committed
- [ ] Tables / collections used by the adapter not exposed via other routes (no `prisma.account.findMany()` in public
      handlers - exposes provider tokens)

## 7. Email / Magic Link

**Checklist:**
- [ ] Magic-link tokens single-use, time-limited (default behavior)
- [ ] Email-sending route rate-limited per email address (otherwise account-spam vector)
- [ ] Email template does not leak token in URL via referrer (`Referrer-Policy: no-referrer` on the consume page)

## 8. Edge / Middleware Auth

**Red Flags:**
```ts
// VULNERABLE - middleware checks token presence, not validity (signature might fail silently)
export { default } from "next-auth/middleware";                 // NextAuth v4
// Auth.js v5: export const { auth } = NextAuth(...); export default auth;
```

**Checklist:**
- [ ] Auth-aware middleware (`next-auth/middleware`, Auth.js v5 `auth()`) covers all protected paths via `matcher`
- [ ] Edge runtime constraints: do not call Node-only `crypto` from edge middleware - use the JWT verification helpers
      provided by Auth.js
- [ ] `getServerSession` / `auth()` called in server components and route handlers for protected logic - middleware
      alone is not sufficient if matcher misses a path

## References

- NextAuth: https://next-auth.js.org/
- Auth.js v5: https://authjs.dev/
