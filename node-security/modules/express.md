---
name: Express Security Patterns
description: Middleware order, body limits, trust proxy, helmet, CORS, error handlers, csurf deprecation
applies_to:
  - framework: express
  - dependency: express
version: 1
last_updated: 2026-04-30
---

# Express Security Patterns

Apply when the project uses Express. Connect-style middleware shares most of these.

## 1. Middleware Order

**Red Flags:**
```js
// VULNERABLE - route mounted before auth
const app = express();
app.get("/admin", adminHandler);                                // public; auth never checked
app.use(authMiddleware);

// VULNERABLE - body parser after CSRF
app.use(csrf());                                                // tokens read before body is parsed; fails open in some configs
app.use(express.json());

// VULNERABLE - error handler missing async-safe variant on Express 4
app.get("/x", async (req, res) => {                             // throws -> hangs request, no error to next()
  await dangerous();
});

// SAFE
app.use(helmet());
app.use(express.json({ limit: "100kb" }));
app.use(authMiddleware);
app.use(csrf());                                                // only if cookie-based session; see CSRF below
app.get("/admin", requireAdmin, adminHandler);
app.use((err, req, res, next) => { /* error handler always last */ });
```

**Checklist:**
- [ ] Auth/session/CSRF/security-header middleware mounted *before* any protected route
- [ ] Routes registered after their middleware, not before
- [ ] Express 4: async handlers use `express-async-errors` (patches the framework) or wrap with `(req,res,next)=>fn(req,res,next).catch(next)`
- [ ] Express 5: native async support; verify project is on 5.x for new code
- [ ] Final error handler with 4-arg signature `(err, req, res, next)` mounted last; does not leak stack in production

## 2. Body Limits

**Red Flags:**
```js
// VULNERABLE - no explicit limit (default is 100kb but easily increased; also forgotten in `urlencoded` /
// `text` / `raw`)
app.use(express.json({ limit: "100mb" }));

// VULNERABLE - urlencoded with high parameterLimit allows array-prototype-pollution probe
app.use(express.urlencoded({ extended: true, parameterLimit: 100000 }));
```

**Checklist:**
- [ ] `express.json({ limit })` set explicitly; default 100kb fine for most APIs
- [ ] Pre-auth endpoints (login, register, password reset) use a *tighter* body limit (~32-64 KiB)
- [ ] `express.urlencoded({ extended: false })` if nested objects not needed; reduces qs parser surface
- [ ] `parameterLimit` and `arrayLimit` (qs option) bounded on `urlencoded`
- [ ] Webhook routes use `express.raw({ type: "application/json", limit })` *before* `express.json` to keep raw body for
      HMAC verification

## 3. trust proxy

**Red Flags:**
```js
// VULNERABLE - trusts arbitrary X-Forwarded-* hop count
app.set("trust proxy", true);
app.set("trust proxy", "*");
```

**Checklist:**
- [ ] `app.set("trust proxy", ...)` set to a specific number of hops (e.g. `1` for single nginx in front) or a CIDR
      list, not blanket `true`
- [ ] If app port is exposed to the internet directly (no proxy), `trust proxy` left at default `false`
- [ ] `req.ip`, `req.protocol`, `req.hostname`, `req.secure` reads audited - they all derive from forwarded headers
      when `trust proxy` is on
- [ ] See `SKILL.md` "Forwarded-Header Trust"

## 4. Helmet / Security Headers

**Red Flags:**
```js
// VULNERABLE - no helmet, x-powered-by leaks framework
const app = express();
app.get("/", (_, res) => res.send("hi"));                       // X-Powered-By: Express

// VULNERABLE - helmet with CSP disabled but no replacement
app.use(helmet({ contentSecurityPolicy: false }));
```

**Checklist:**
- [ ] `helmet()` installed with default config or stricter
- [ ] `app.disable("x-powered-by")` (or rely on helmet's `hidePoweredBy`)
- [ ] CSP configured for HTML-serving routes (default-src 'self'; script-src nonce-based; no `unsafe-inline`/`unsafe-eval`)
- [ ] HSTS only set on HTTPS-only deployments (`hsts: { maxAge, includeSubDomains, preload }`)
- [ ] `frameguard` ('deny' or 'sameorigin') unless app embeds itself in iframes intentionally
- [ ] `referrerPolicy: 'no-referrer'` or `'strict-origin-when-cross-origin'`

## 5. CORS

**Red Flags:**
```js
// VULNERABLE - permissive CORS with credentials
app.use(cors({ origin: "*", credentials: true }));

// VULNERABLE - reflects any Origin
app.use(cors({ origin: (origin, cb) => cb(null, origin) }));    // reflects, with credentials = CSRF
```

**Checklist:**
- [ ] `origin` is an explicit string or array of strings; never `"*"` with `credentials: true`
- [ ] If origin is a callback, it validates against an allowlist; never `cb(null, true)` or `cb(null, origin)`
- [ ] `methods` and `allowedHeaders` minimal
- [ ] `exposedHeaders` minimal (avoid leaking internal headers cross-origin)
- [ ] CORS middleware mounted before auth middleware so preflights succeed; verify preflight is not a CSRF bypass

## 6. CSRF

`csurf` is deprecated as of 2022. Choose:

**Checklist:**
- [ ] If using cookie-session auth: use `csrf-csrf` (double-submit cookie) or `lusca`, OR enforce `SameSite=Strict` on
      session cookie + verify Origin/Referer header server-side
- [ ] If using bearer token auth (Authorization header): not vulnerable to CSRF, but verify endpoints reject the same
      auth via cookie
- [ ] CSRF tokens compared with `crypto.timingSafeEqual`
- [ ] Webhook endpoints exempt from CSRF (they are not browser-driven), but they MUST verify HMAC signature

## 7. Cookie & Session Hygiene

**Red Flags:**
```js
// VULNERABLE - session cookie missing security flags
app.use(session({ secret: "...", resave: false, saveUninitialized: false }));

// SAFE
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: true, sameSite: "lax", maxAge: 86400_000 },
  name: "sid",                                                  // not the default `connect.sid` (fingerprintable)
  store: redisStore,                                            // not MemoryStore in prod
}));
```

**Checklist:**
- [ ] `cookie: { httpOnly, secure, sameSite }` set on every session and auth cookie
- [ ] `secure: true` in production (HTTPS); accept `false` only when `NODE_ENV !== 'production'`
- [ ] `sameSite: 'lax'` minimum; `'strict'` for high-value cookies
- [ ] `MemoryStore` not used in production (warns at startup; lose sessions on restart, leak with multi-process)
- [ ] `secret` is a strong random value loaded from env / secret manager
- [ ] Session ID regenerated on login (`req.session.regenerate(cb)`) - fixation prevention

## 8. send / sendFile / static

**Red Flags:**
```js
// VULNERABLE - path traversal via filename
app.get("/files/:name", (req, res) => res.sendFile(req.params.name, { root: "/srv/data" }));
// `..%2f` paths historically bypassed by some intermediate proxies

// VULNERABLE - static mount overlaps with API routes; precedence accidentally serves uploaded HTML as content
app.use(express.static("uploads"));                              // user-uploaded HTML executes
```

**Checklist:**
- [ ] `res.sendFile` always passes `root` option AND `dotfiles: 'deny'`
- [ ] User-controlled filenames validated (no `..`, no `/`, no `\`, no null byte) - prefer generated UUIDs
- [ ] User-uploaded content not served from `express.static` directly; serve via dedicated route that sets
      `Content-Disposition: attachment` and a safe `Content-Type`
- [ ] HTML/SVG uploads sanitized or rasterized before serving

## 9. Error Handling

**Red Flags:**
```js
// VULNERABLE - leaks stack to clients
app.use((err, req, res, next) => res.status(500).json({ error: err.message, stack: err.stack }));
```

**Checklist:**
- [ ] Production error handler returns generic message + correlation id; full error logged server-side
- [ ] `NODE_ENV=production` set in deployment so Express disables verbose stack traces in default error handler
- [ ] No `errorhandler` middleware in production (intended for development only - leaks code)

## References

- Express security best practices: https://expressjs.com/en/advanced/best-practice-security.html
- helmet: https://helmetjs.github.io/
- csurf deprecation: https://github.com/expressjs/csurf
