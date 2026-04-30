---
name: Fastify Security Patterns
description: Schema-first validation, hooks, bodyLimit, trustProxy, CORS, JWT plugin, raw body for webhooks
applies_to:
  - framework: fastify
  - dependency: fastify
version: 1
last_updated: 2026-04-30
---

# Fastify Security Patterns

Apply when the project uses Fastify. Fastify's schema-first design eliminates many input issues
when used correctly; the most common bug is *not* declaring a schema.

## 1. Schema Validation

**Red Flags:**
```js
// VULNERABLE - no schema; body/query/params are `unknown`
fastify.post("/users", async (req) => {
  return User.create(req.body);                                 // mass assignment, unbounded fields
});

// SAFE - schema constrains shape and length
fastify.post("/users", {
  schema: {
    body: {
      type: "object",
      required: ["email", "name"],
      additionalProperties: false,                              // strips unknown keys (mass-assignment defense)
      properties: {
        email: { type: "string", format: "email", maxLength: 320 },
        name: { type: "string", maxLength: 255 },
      },
    },
  },
}, async (req) => User.create(req.body));
```

**Checklist:**
- [ ] Every route declares `schema` for `body`, `querystring`, `params`, `headers` where relevant
- [ ] `additionalProperties: false` set on body schemas (prevents mass assignment)
- [ ] String fields have `maxLength`; numeric fields have `minimum` / `maximum`
- [ ] Pre-auth routes have the tightest body schemas
- [ ] `response` schema declared - prevents leaking ORM internals (Fastify serializes only schema-listed fields by
      default)

## 2. Auth via Hooks / Decorators

**Red Flags:**
```js
// VULNERABLE - decorator declared but not invoked
fastify.decorate("authenticate", async (req) => { /* verify JWT */ });
fastify.get("/admin", async (req) => secrets);                  // forgot { preHandler: [fastify.authenticate] }

// VULNERABLE - register order means auth plugin not loaded for some routes
fastify.register(adminRoutes);                                  // before auth plugin
fastify.register(authPlugin);
```

**Checklist:**
- [ ] Protected routes declare `preHandler` (or `onRequest`) that calls the auth decorator
- [ ] Plugins (auth, rate-limit, CORS) registered *before* route plugins
- [ ] Encapsulation boundaries (`fastify.register(plugin, { prefix })`) reviewed - hooks declared inside one plugin do
      not apply outside
- [ ] Admin routes use a separate decorator (`fastify.requireAdmin`) layered on top, not an `if (req.user.isAdmin)` in
      the handler

## 3. Body Limit

**Red Flags:**
```js
// VULNERABLE - global override
const fastify = Fastify({ bodyLimit: 100 * 1024 * 1024 });      // 100MB
```

**Checklist:**
- [ ] `bodyLimit` set explicitly (default 1 MB); override per-route only when needed
- [ ] Pre-auth endpoints use a per-route `bodyLimit` of ~64 KiB
- [ ] File-upload routes use `@fastify/multipart` with `limits: { fileSize, files, fields }`

## 4. trustProxy

**Red Flags:**
```js
// VULNERABLE - trusts all hops
const fastify = Fastify({ trustProxy: true });
```

**Checklist:**
- [ ] `trustProxy` set to specific IPs / CIDRs / hop count, not `true`
- [ ] App port not directly exposed; only the proxy is reachable
- [ ] `req.ip`, `req.protocol`, `req.hostname` audited - all derive from forwarded headers when `trustProxy` is on

## 5. CORS / Helmet

**Checklist:**
- [ ] `@fastify/cors` registered with explicit `origin` allowlist; never `"*"` with `credentials: true`
- [ ] `@fastify/helmet` registered (sets security headers)
- [ ] CSP configured for HTML-serving routes; default for API-only is `{ contentSecurityPolicy: false }` plus
      `default-src 'none'` if you serve any HTML at all

## 6. JWT (`@fastify/jwt`)

**Red Flags:**
```js
// VULNERABLE - secret only, no algorithm restriction
fastify.register(jwt, { secret: "..." });

// SAFE
fastify.register(jwt, {
  secret: process.env.JWT_SECRET,
  sign: { algorithm: "HS256", expiresIn: "1h", iss: "https://issuer", aud: "my-api" },
  verify: { algorithms: ["HS256"], audience: "my-api", issuer: "https://issuer" },
});
```

**Checklist:**
- [ ] `verify.algorithms` pinned (never accept `none`)
- [ ] `audience` and `issuer` validated
- [ ] `expiresIn` set on signed tokens
- [ ] `secret` from env / KMS, not committed
- [ ] See SKILL.md "JWT" + `modules/custom-jwt.md` for end-to-end coverage

## 7. Raw Body for Webhooks

**Red Flags:**
```js
// VULNERABLE - default JSON parser consumes raw body before HMAC verifier runs
fastify.post("/webhook", async (req) => {
  verifyHmac(JSON.stringify(req.body), req.headers["x-signature"]);  // re-serialized != original bytes
});

// SAFE
fastify.addContentTypeParser("application/json", { parseAs: "buffer" }, (req, body, done) => {
  req.rawBody = body;
  try { done(null, JSON.parse(body.toString())); } catch (e) { done(e); }
});
fastify.post("/webhook", async (req) => {
  verifyHmac(req.rawBody, req.headers["x-signature"]);
});
```

**Checklist:**
- [ ] Webhook routes have access to the raw bytes (custom content type parser, or `request.rawBody` via
      `fastify-raw-body`)
- [ ] HMAC compared with `crypto.timingSafeEqual`
- [ ] Timestamp/replay window enforced; see SKILL.md "Webhook Signature Verification"

## 8. Rate Limiting

**Checklist:**
- [ ] `@fastify/rate-limit` registered globally and/or per-route on auth endpoints
- [ ] Rate-limit key is account / user identifier when authenticated, IP when not (with awareness that proxy chains
      can spoof IP)

## 9. Cookies

**Checklist:**
- [ ] `@fastify/cookie` configured with `secret` (signed cookies) for auth-relevant cookies
- [ ] `@fastify/session` (or `@fastify/secure-session`) cookies set `httpOnly`, `secure`, `sameSite`
- [ ] Production uses a real session store (redis), not in-memory

## References

- Fastify validation: https://fastify.dev/docs/latest/Reference/Validation-and-Serialization/
- Fastify ecosystem: https://fastify.dev/ecosystem
