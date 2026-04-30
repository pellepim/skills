---
name: Koa Security Patterns
description: Middleware order, koa-bodyparser limits, koa-helmet, koa-router auth, koa-session
applies_to:
  - framework: koa
  - dependency: koa
version: 1
last_updated: 2026-04-30
---

# Koa Security Patterns

Apply when the project uses Koa or Koa-router.

## 1. Middleware Order

**Red Flags:**
```js
// VULNERABLE - bodyparser before security headers; handler before auth
app.use(bodyParser());
app.use(handler);                                               // unauthenticated

// SAFE
app.use(helmet());
app.use(bodyParser({ jsonLimit: "100kb", formLimit: "100kb", textLimit: "100kb" }));
app.use(authMiddleware);
app.use(router.routes()).use(router.allowedMethods());
```

**Checklist:**
- [ ] Auth middleware mounted before any protected route's router
- [ ] `koa-bodyparser` limits set explicitly (`jsonLimit`, `formLimit`, `textLimit`) - default is 1mb
- [ ] `koa-helmet` registered for security headers
- [ ] Error handler at top of chain catches downstream throws (Koa's `app.on('error')` for logging only - does not
      sanitize the response)

## 2. Body Parser Limits

**Checklist:**
- [ ] `koa-bodyparser` (or `@koa/bodyparser` for Koa 2+) configured with explicit limits
- [ ] Pre-auth endpoints use a tighter per-route limit (~64 KiB)
- [ ] `enableTypes` restricted to needed types (e.g. `['json']` if only JSON expected)

## 3. trust proxy / Forwarded Headers

**Checklist:**
- [ ] `app.proxy = true` only when actually behind a trusted proxy
- [ ] `app.proxyIpHeader` / `app.maxIpsCount` configured; do not blindly accept all hops
- [ ] `ctx.ip`, `ctx.protocol`, `ctx.host` reads audited - they all derive from forwarded headers when `app.proxy` is
      true

## 4. CORS

**Red Flags:**
```js
// VULNERABLE - permissive
app.use(cors({ origin: "*", credentials: true }));
```

**Checklist:**
- [ ] `@koa/cors` configured with explicit origin allowlist; never `'*'` with credentials
- [ ] Origin function validates against allowlist; never reflects arbitrary origin

## 5. CSRF

**Checklist:**
- [ ] Cookie-session apps use `koa-csrf` or hand-rolled double-submit pattern
- [ ] Tokens compared with `crypto.timingSafeEqual`
- [ ] `SameSite=Lax` minimum on session cookies

## 6. Sessions / Cookies

**Red Flags:**
```js
// VULNERABLE - default cookie options leave Secure/HttpOnly/SameSite unset
app.use(session({ key: "sess", maxAge: 86400000 }, app));

// SAFE
app.use(session({
  key: "sid",
  maxAge: 86400000,
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  signed: true,
}, app));
app.keys = [process.env.SESSION_SECRET, process.env.SESSION_SECRET_OLD].filter(Boolean);
```

**Checklist:**
- [ ] `koa-session` cookie options set: `httpOnly: true`, `secure: true` (prod), `sameSite: 'lax'`
- [ ] `app.keys` array supports rotation; old key stays valid one cycle
- [ ] `koa-session` cookies signed (`signed: true`)
- [ ] Production uses external store, not in-memory

## 7. Static / Send

**Red Flags:**
```js
// VULNERABLE - no root option means traversal possible
const send = require("koa-send");
await send(ctx, ctx.params.path);

// SAFE
await send(ctx, ctx.params.path, { root: "/srv/data", hidden: false });
```

**Checklist:**
- [ ] `koa-send` always passes `root` AND `hidden: false`
- [ ] User-controlled filenames validated; prefer generated UUIDs
- [ ] `koa-static` does not overlap with user-uploaded paths

## 8. Error Handling

**Checklist:**
- [ ] Top-level error middleware sets generic error message in production; full error logged
- [ ] No `JSON.stringify(err)` in response (leaks stack, internal paths)

## References

- Koa docs: https://koajs.com/
- @koa/bodyparser: https://github.com/koajs/bodyparser
