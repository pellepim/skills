---
name: node-security
description: Security Agent - Identify OWASP Top 10 vulnerabilities and security issues in Node.js / JavaScript / TypeScript projects
version: 1
last_updated: 2026-04-29
---

# Security Agent - Vulnerability Assessment Mode (Node / JS / TS)

Identify OWASP Top 10 vulnerabilities and security misconfigurations in Node.js / JavaScript / TypeScript backends and
isomorphic apps.

## Quick Reference

- **Reads:** Codebase (especially auth, database, templates, API routes, middleware)
- **Writes:** Findings report only
- **Can commit:** No

## OWASP Categories

| Category                  | Code | Focus Area                                                                                              |
|---------------------------|------|---------------------------------------------------------------------------------------------------------|
| Broken Access Control     | A01  | Ownership checks, IDOR, privilege escalation, CSRF                                                      |
| Cryptographic Failures    | A02  | Password hashing, token generation, JWT, TLS verification, timing attacks, weak ciphers, data exposure  |
| Injection                 | A03  | SQL / NoSQL, XSS, command injection, SSTI, XXE, path traversal, log injection                           |
| Insecure Design           | A04  | Mass assignment, business-logic flaws, missing rate limits on sensitive flows                           |
| Security Misconfiguration | A05  | CORS, cookies, headers, debug mode, trusted-proxy boundaries                                            |
| Vulnerable Components     | A06  | Dependency scanning (`npm audit`, `osv-scanner`, `pnpm audit`)                                          |
| Auth Failures             | A07  | Password handling, session management, MFA, webhook signature verification                              |
| Data Integrity            | A08  | Deserialization, prototype pollution, `eval`, decompression bombs                                       |
| Logging Failures          | A09  | Auth events, log injection                                                                              |
| SSRF                      | A10  | URL fetching with user input, metadata endpoint, DNS rebinding                                          |
| Unbounded Input           | -    | Missing length limits on string fields, unbounded JSON bodies                                           |
| Resource Exhaustion       | -    | ReDoS, decompression bombs, unbounded recursion, event-loop starvation                                  |
| Race / TOCTOU             | -    | Async shared state, idempotency, file create-then-check                                                 |
| Prototype Pollution       | -    | `Object.assign`/merge/clone with attacker-controlled keys (`__proto__`, `constructor`, `prototype`)     |
| Policy Consistency        | -    | Settings/UI promise X but code does not enforce X                                                       |

## Optional Modules (Dynamic Discovery)

Modules live in `modules/*.md`. Each declares triggers in YAML frontmatter:

```yaml
---
name: <module name>
description: <one-liner>
applies_to:
  - feature: <name>      # explicit feature name
  - framework: <name>    # express, fastify, nestjs, koa, next-api
  - dependency: <npm>    # detect via package.json / package-lock.json / pnpm-lock.yaml / yarn.lock
  - any                  # always-on
version: <int>
last_updated: <YYYY-MM-DD>
---
```

**Discovery procedure (run at scan start):**

1. List `modules/*.md` (skip files starting with `_`, e.g. `_template.md`, `_index.md`).
2. Parse each module's frontmatter `applies_to`.
3. For each trigger:
   - `feature:` — match against user-stated scope, or grep evidence (e.g. `saml` ↔ `samlp:`, `oauth2` ↔ `/authorize`,
     `webauthn` ↔ `navigator.credentials`, `graphql` ↔ `type Query`).
   - `framework:` — match imports / app construction (`require('express')` / `from 'express'` → express,
     `from 'fastify'` → fastify, `@nestjs/core` → nestjs, `next` with `pages/api` or `app/api` → next-api).
   - `dependency:` — match against `package.json` (`dependencies`, `devDependencies`), `package-lock.json`,
     `pnpm-lock.yaml`, `yarn.lock`.
   - `any` — always load.
4. Read every matched module and apply its checklists during the scan.
5. Record in the report which modules were loaded and which were skipped (with reason).

`modules/_index.md` is a human-readable summary of available modules. `modules/_template.md` is the contract for new
modules.

**Adding a module:** copy `_template.md`, fill frontmatter, write Red Flags + Checklists. No edit to `SKILL.md` needed.

## Workflow

### 0. Static Analyzer Pre-Pass

Before manual review, run the cheap automated checks. They catch the obvious cases and let manual review focus on what
tools cannot see (auth logic, IDOR, policy consistency, business logic).

See `tools/` for invocation details. Quick reference:

```bash
# Dependencies
npm audit --omit=dev                                   # known CVEs (use pnpm/yarn equivalent)
osv-scanner --lockfile=package-lock.json               # broader CVE DB
# JS/TS lints
npx eslint --ext .js,.ts,.tsx \
  --rule 'security/detect-object-injection: warn' \
  --rule 'security/detect-non-literal-fs-filename: warn' .
# Pattern-based
semgrep --config=p/javascript --config=p/typescript \
        --config=p/owasp-top-ten --baseline-ref=origin/main .
# Secrets
gitleaks detect --log-opts="origin/main..HEAD" -v
```

Triage tool output before reporting:
- High-confidence findings (e.g. `child_process.exec(userInput)`, `eval(req.body)`, `rejectUnauthorized: false`) →
  include directly.
- Medium-confidence (e.g. `eslint-plugin-security` `detect-object-injection`) → verify reachability with user input
  first; this rule is famously noisy.
- Known false positives → suppress with rule ID + reason inline (`// eslint-disable-next-line security/detect-object-injection -- key is from a static enum`).

Tool output is a starting point, not the report.

### 1. Orientation

Ask the user:
- **Scope:** Full assessment or specific area?
- **Focus:** All categories or specific concern?
- **Context:** First review, verification, or known concern?

### 2. Systematic Scanning

#### Injection (A03)

**SQL Injection — Red Flags:**
```js
// VULNERABLE - template literal with user input
const q = `SELECT * FROM users WHERE email = '${email}'`;
db.query(q);
db.query("SELECT * FROM users WHERE email = '" + email + "'");

// VULNERABLE - knex.raw with interpolation
knex.raw(`SELECT * FROM users WHERE id = ${id}`);

// SAFE - parameterized
db.query("SELECT * FROM users WHERE email = $1", [email]);          // pg
db.query("SELECT * FROM users WHERE email = ?", [email]);           // mysql2
knex("users").where({ email });                                     // query builder
knex.raw("SELECT * FROM users WHERE id = ?", [id]);                 // bound params
```

**SQL Injection — Checklist:**
- [ ] Search for `` ` `` (template literals) near SQL keywords (SELECT/INSERT/UPDATE/DELETE)
- [ ] Search for `+` string concatenation near SQL
- [ ] `knex.raw(...)`, `sequelize.query(...)`, `pool.query(...)` calls use bound parameters, not interpolation
- [ ] Prisma `$queryRawUnsafe` / `$executeRawUnsafe` not used with user input — prefer `$queryRaw` (tagged template
      bindings)
- [ ] TypeORM `query()` / `createQueryBuilder().where("col = " + x)` — uses parameter object, not concat
- [ ] Dynamic table/column names validated against allowlists
- [ ] Search/filter endpoints escape LIKE wildcards (`%`, `_`)
- [ ] See `modules/prisma.md`, `modules/typeorm.md`, `modules/sequelize.md`, `modules/knex.md` for ORM specifics

**NoSQL Injection — Red Flags:**
```js
// VULNERABLE - object body splatted into Mongo query (operator injection)
User.findOne({ email: req.body.email, password: req.body.password });
// attacker posts {"email":"a@b","password":{"$ne":""}} -> matches any password

// VULNERABLE - $where with user input
User.find({ $where: `this.username == '${username}'` });

// SAFE - cast to primitive before query
User.findOne({ email: String(req.body.email) });
// then verify password via bcrypt.compare on the hash
```

**NoSQL Injection — Checklist:**
- [ ] Inputs going into Mongo / Mongoose queries are coerced to primitives (`String(x)`, `Number(x)`) or validated by a
      schema (zod, joi, ajv) before being used as query operands
- [ ] No `$where`, `mapReduce`, `$function`, `$accumulator` with user input (these execute JS server-side)
- [ ] Use `express-mongo-sanitize` or equivalent to strip `$`-prefixed keys from req.body / req.query
- [ ] See `modules/mongoose.md` for full coverage

**XSS — Red Flags:**
```jsx
// VULNERABLE - React dangerouslySetInnerHTML with user input
<div dangerouslySetInnerHTML={{ __html: post.body }} />

// VULNERABLE - raw output in template
// Pug:    != user.bio        (unescaped)
// Handlebars: {{{ user.bio }}}  (triple-stash = unescaped)
// EJS:    <%- user.bio %>    (unescaped)
// Nunjucks: {{ user.bio | safe }}

// VULNERABLE - innerHTML with interpolation in browser/SSR
el.innerHTML = `<p>${data.name}</p>`;

// SAFE
<div>{post.body}</div>                              // React auto-escapes
// Pug:    #{user.bio}
// Handlebars: {{ user.bio }}
// EJS:    <%= user.bio %>
// el.textContent = data.name;
// or sanitize: DOMPurify.sanitize(html)
```

**XSS — Checklist:**
- [ ] Search templates for unescaped output: `{{{` (Handlebars), `!=` (Pug), `<%- %>` (EJS), `| safe` (Nunjucks)
- [ ] Search React/Preact for `dangerouslySetInnerHTML` — every hit must wrap input in DOMPurify or be a static string
- [ ] `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write` audited; prefer `textContent`
- [ ] User-provided URLs (`href`, `src`, `formaction`) reject `javascript:`, `data:` schemes
- [ ] CSP header configured (Helmet `contentSecurityPolicy` middleware or framework equivalent)
- [ ] Email HTML / PDF rendering sanitizes user input before passing to renderer

**Command Injection — Red Flags:**
```js
// VULNERABLE - exec with interpolation
const { exec } = require("child_process");
exec(`convert ${filename} out.png`);
exec("git clone " + repoUrl);
require("child_process").execSync(`ping ${host}`);

// VULNERABLE - shell: true on spawn
spawn("sh", ["-c", `tar -xf ${file}`]);
spawn(cmd, args, { shell: true });

// SAFE - argv array, no shell
const { execFile, spawn } = require("child_process");
execFile("convert", [filename, "out.png"]);
spawn("git", ["clone", repoUrl]);
spawn("tar", ["-xf", file]);                        // shell: false (default)
```

**Command Injection — Checklist:**
- [ ] Grep for `child_process.exec(`, `execSync(`, `child_process.execFile(...{shell:true})` — every hit must use a
      static command or `shell-escape`/`shell-quote` on every interpolated value
- [ ] Prefer `execFile` / `spawn` with argv array over `exec` (exec routes through `/bin/sh -c`)
- [ ] `shell: true` option only with static command strings, never with interpolated user input
- [ ] `git`, `convert`, `ffmpeg`, `pdftk`, `tar`, `unzip`, `youtube-dl`/`yt-dlp` invocations use argv array form
- [ ] PATH not user-controllable (`env` option for spawned processes filters / overrides PATH)

**SSTI (Server-Side Template Injection) — Red Flags:**
```js
// VULNERABLE - Handlebars compiling user-controlled template
const template = Handlebars.compile(req.body.template);
template({ user });

// VULNERABLE - EJS render with user template
ejs.render(req.body.template, { user });

// VULNERABLE - Pug compile from user input
const fn = pug.compile(userTemplateString);

// VULNERABLE - Nunjucks renderString of user input
nunjucks.renderString(userTemplate, ctx);

// SAFE - render fixed template, pass user data as variable
res.render("greeting", { name });                   // Express + view engine
nunjucks.render("greeting.njk", { name });
```

**SSTI — Checklist:**
- [ ] No user input passed as template *source* to `compile(...)`, `renderString(...)`, `Handlebars.compile`,
      `ejs.render(str, ...)`, `pug.compile(...)`
- [ ] User input only passed as *variables* into pre-authored templates
- [ ] If user-authored templates are a feature (CMS, email templates), assume sandbox bypass exists; isolate the
      renderer (separate process / VM with no network and no `require`)
- [ ] Grep for `compile(`, `renderString(`, `template(` near request data

**XXE / Unsafe XML — Red Flags:**
```js
// VULNERABLE - libxmljs2 with default options resolves entities
const libxmljs = require("libxmljs2");
libxmljs.parseXmlString(userXml);                   // noent / external entity defaults vary

// VULNERABLE - xml2js with explicit entity resolution
const parser = new xml2js.Parser({ explicitArray: false });
parser.parseString(userXml, cb);                    // verify build does not enable DTD/entity loading

// VULNERABLE - sax-style parsers that fetch external DTDs
// VULNERABLE - SOAP libs (strong-soap, easy-soap-request) without disabling DTD

// SAFE - libxmljs2 with no DTD/network
libxmljs.parseXmlString(userXml, { noent: false, dtdload: false, dtdvalid: false, nonet: true });

// SAFE - fast-xml-parser (no entity resolution by default)
const { XMLParser } = require("fast-xml-parser");
new XMLParser().parse(userXml);
```

**XXE — Checklist:**
- [ ] `libxmljs` / `libxmljs2` parsers explicitly disable DTD loading and network access
- [ ] `xml2js`, `xmldom` defaults reviewed; prefer `fast-xml-parser` for untrusted input
- [ ] SOAP/SAML/OOXML/SVG/RSS/Atom parsers reviewed (all are XML)
- [ ] DOCTYPE declarations rejected on untrusted input
- [ ] SVG uploads sanitized (`DOMPurify` with SVG profile, or rasterize)

**Path Traversal — Red Flags:**
```js
// VULNERABLE
fs.readFileSync(path.join(BASE_DIR, req.query.name));        // "../../etc/passwd"
fs.createReadStream(`uploads/${req.params.path}`);
res.sendFile(path.join("/srv/data", req.params.file));
fs.unlinkSync(req.body.path);

// VULNERABLE - resolve() not boundary-checked
const target = path.resolve(BASE_DIR, req.params.name);
return fs.readFileSync(target);                              // .. or symlink can escape

// SAFE - resolve and verify under base
const base = path.resolve(BASE_DIR);
const target = path.resolve(base, req.params.name);
if (!target.startsWith(base + path.sep) && target !== base) {
  throw new Error("path traversal");
}
return fs.readFileSync(target);
```

**Path Traversal — Checklist:**
- [ ] Every `fs.*` (`readFile`, `writeFile`, `createReadStream`, `unlink`, `rename`, `rm`) and `res.sendFile` /
      `res.download` on user input goes through a base-directory boundary check
- [ ] Use `path.resolve` then prefix-check with `path.sep` boundary; do not rely on `startsWith(base)` alone
      (`/srv/data2` matches `/srv/data` prefix)
- [ ] Reject filenames containing `..`, `/`, `\`, null bytes (`\0`), and Windows drive prefixes (`C:`)
- [ ] Prefer generated identifiers (UUID + extension) over user-supplied names
- [ ] Symlink-following ops considered: attacker may upload a symlink and read across it; use
      `fs.realpathSync` + boundary check or refuse symlinks
- [ ] On Windows, watch for `\\?\`, `\\.\`, NTFS alternate data streams (`file::$DATA`)

#### Authentication (A07)

**Red Flags:**
```js
// VULNERABLE - weak hashing
crypto.createHash("md5").update(password).digest("hex");
crypto.createHash("sha256").update(password).digest("hex");

// VULNERABLE - hand-rolled HMAC-as-password (still not memory-hard)
crypto.createHmac("sha256", salt).update(password).digest("hex");

// SAFE
await bcrypt.hash(password, 12);                    // bcrypt
await argon2.hash(password);                        // argon2 (preferred)
```

**Checklist:**
- [ ] Password hashing uses bcrypt (cost ≥10) or argon2id (preferred), never MD5/SHA1/SHA256/PBKDF2 with low iterations
- [ ] Session tokens use `crypto.randomBytes(32).toString("base64url")` or `crypto.randomUUID()` (never `Math.random()`,
      never sequential integers)
- [ ] Session regenerates on login (express-session: `req.session.regenerate(...)`) — fixation prevention
- [ ] Rate limiting on auth endpoints (express-rate-limit, fastify-rate-limit, or upstream WAF)
- [ ] Password reset tokens are single-use, time-limited, stored as hashes (compare with `crypto.timingSafeEqual`)
- [ ] Unauthenticated endpoints with side effects (email sends, signup verification) have rate limiting

#### Access Control (A01)

**Red Flags:**
```js
// VULNERABLE - no ownership check
app.get("/documents/:id", async (req, res) => {
  res.json(await Document.findById(req.params.id)); // Who owns this?
});

// SAFE
app.get("/documents/:id", requireAuth, async (req, res) => {
  const doc = await Document.findById(req.params.id);
  if (!doc || doc.ownerId !== req.user.id) return res.sendStatus(404);
  res.json(doc);
});
```

```js
// VULNERABLE - policy check only at HTTP layer, not business logic
app.post("/profile", (req, res) => {
  if (!settings.allowUsersEditProfile) return res.sendStatus(403);
  return service.updateProfile(req.body);           // service can be called from worker / other route
});

// SAFE - policy check in service layer
function updateProfile(user, data) {
  if (!canUserEditProfile(user)) throw new ForbiddenError();
  // ...
}
```

**Checklist:**
- [ ] All endpoints verify resource ownership (or membership / role match)
- [ ] IDOR prevention (cannot access others' resources by changing IDs in path/body/query)
- [ ] Role checks prevent privilege escalation; admin-only endpoints layer a separate middleware (`requireAdmin`), not an
      `if (user.isAdmin)` inside the handler
- [ ] Auth middleware applied at router scope — every protected route inherits it; not opt-in per route (easy to forget)
- [ ] Policy checks enforced in business logic / service layer, not just HTTP middleware
- [ ] CRUD lifecycle consistency (if create requires elevated role, update/delete should too)
- [ ] Express: `app.use(authMiddleware)` order audited; routes mounted before the middleware are public

#### Cryptographic Failures (A02)

**Sensitive Data Exposure — Red Flags:**
```js
// VULNERABLE
logger.debug(`User login: ${email}, password: ${password}`);
res.status(500).json({ error: err.message, stack: err.stack });
const SECRET_KEY = "hardcoded-secret-123";
```

**Sensitive Data — Checklist:**
- [ ] Passwords never logged (including request-body loggers — strip `password`, `token`, `secret`, `authorization`)
- [ ] API responses do not leak internal fields (stack traces, DB errors, ORM model with `passwordHash`)
- [ ] Error responses generic in production (`NODE_ENV=production`); detailed only in dev
- [ ] Secrets not hardcoded in source (grep for `SECRET`, `KEY`, `TOKEN`, `PASSWORD` in `.js`/`.ts`/`.env.example`)
- [ ] Sensitive data not in URL parameters (appears in logs, referrer headers, browser history)

**Weak Randomness — Red Flags:**
```js
// VULNERABLE - Math.random is NOT cryptographically secure
const token = Math.random().toString(36).slice(2);
const otp = Math.floor(Math.random() * 900000) + 100000;
const sessionId = Date.now().toString(36) + Math.random();

// SAFE
import { randomBytes, randomInt, randomUUID } from "node:crypto";
const token = randomBytes(32).toString("base64url");
const otp = randomInt(100000, 1000000);
const sessionId = randomUUID();                     // UUID v4 (random); never v1 (timestamp-based)
```

**Weak Randomness — Checklist:**
- [ ] `Math.random()` not used for tokens, session IDs, OTPs, password reset codes, nonces, keys
- [ ] `uuid` v1 / v3 / v5 not used for security-relevant IDs (use `uuid.v4` or `crypto.randomUUID`)
- [ ] `crypto.randomBytes`, `crypto.randomInt`, `crypto.randomUUID` for all security-sensitive randomness
- [ ] `Date.now()` not used as the sole entropy source for tokens

**Timing Attacks — Red Flags:**
```js
// VULNERABLE - == / === leak timing
if (apiKey === storedKey) { /* ... */ }
if (token == expected) { /* ... */ }
if (hmacDigest === provided) { /* ... */ }

// SAFE
import { timingSafeEqual } from "node:crypto";
const a = Buffer.from(apiKey);
const b = Buffer.from(storedKey);
if (a.length === b.length && timingSafeEqual(a, b)) { /* ... */ }
```

**Timing — Checklist:**
- [ ] Secret/token/HMAC/signature comparison uses `crypto.timingSafeEqual`, never `==` / `===`
- [ ] Buffers compared with `timingSafeEqual` are equal length (the function throws otherwise; pre-check length to avoid
      a length-leak side channel via thrown vs not-thrown)
- [ ] Constant-time comparison for password verification (handled by bcrypt/argon2 verify functions; do not roll your
      own)

**JWT — Red Flags:**
```js
// VULNERABLE - no algorithm restriction (alg=none accepted)
jwt.verify(token, secret);
jwt.verify(token, secret, { algorithms: ["none"] });

// VULNERABLE - decode without verify (just returns claims, no signature check)
jwt.decode(token);                                  // never trust output for auth

// VULNERABLE - accepts both HS256 and RS256 (algorithm confusion when key is RSA pub)
jwt.verify(token, publicKeyPem, { algorithms: ["HS256", "RS256"] });

// VULNERABLE - no aud/iss validation
jwt.verify(token, key, { algorithms: ["RS256"] });  // missing audience/issuer

// SAFE
jwt.verify(token, key, {
  algorithms: ["RS256"],
  audience: "my-api",
  issuer: "https://issuer.example",
  clockTolerance: 30,
});
```

**JWT — Checklist:**
- [ ] `algorithms:` always passed explicitly; never trust the `alg` header
- [ ] `none` algorithm rejected (do not include in `algorithms`)
- [ ] `HS256` and `RS256` not both accepted with the same key material (algorithm confusion)
- [ ] `aud` and `iss` claims validated
- [ ] `exp` enforced; clock skew bounded (typical 30-60s leeway)
- [ ] `kid` header values constrained (no path traversal in JWKS lookups)
- [ ] HMAC keys have ≥256 bits of entropy (random, not "secret")
- [ ] Public/private key pairs not committed; rotated with overlap window
- [ ] `jwt.decode()` never used as a substitute for `verify()`
- [ ] See `modules/custom-jwt.md` for end-to-end coverage

**TLS Verification — Red Flags:**
```js
// VULNERABLE
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";     // disables verification globally
const agent = new https.Agent({ rejectUnauthorized: false });
fetch(url, { agent: new https.Agent({ rejectUnauthorized: false }) });
axios.get(url, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
got(url, { https: { rejectUnauthorized: false } });

// SAFE - default rejectUnauthorized: true; for custom CA bundle:
const agent = new https.Agent({ ca: fs.readFileSync("/etc/ssl/internal-ca.pem") });
```

**TLS — Checklist:**
- [ ] No `rejectUnauthorized: false` on `https`, `tls`, `axios`, `got`, `node-fetch`, `undici`
- [ ] `NODE_TLS_REJECT_UNAUTHORIZED=0` not set anywhere (env, Dockerfile, k8s manifest, npm scripts)
- [ ] Internal services with private CA use `ca:` option, not disabled verification
- [ ] Test fixtures with disabled verify isolated to test code (grep for `rejectUnauthorized: false` outside `test*`,
      `__tests__`, `*.spec.*`, `*.test.*`)

**Symmetric Crypto — Red Flags:**
```js
// VULNERABLE - ECB mode (patterns leak), DES, MD5/SHA1 for HMAC
crypto.createCipheriv("aes-256-ecb", key, null);
crypto.createCipheriv("des-cbc", key, iv);

// VULNERABLE - reused IV with AES-GCM (catastrophic)
const iv = Buffer.alloc(12, 0);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);   // same iv across messages

// SAFE - AES-GCM with fresh IV per message
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
const tag = cipher.getAuthTag();
// store/transmit iv + tag alongside ct
```

**Symmetric Crypto — Checklist:**
- [ ] No ECB mode for anything except single-block primitives
- [ ] No DES / 3DES / RC4 / MD5 / SHA1 for new code
- [ ] AEAD (AES-GCM, ChaCha20-Poly1305) preferred over unauthenticated CBC/CTR
- [ ] IVs / nonces random per-message (`crypto.randomBytes`) or strict counter; never reused with the same key
- [ ] AES-GCM `getAuthTag()` / `setAuthTag()` invoked; without auth tag, GCM is a stream cipher
- [ ] Keys come from a KMS / secret store, not hardcoded or `.env` in repo
- [ ] No hand-rolled crypto; no `crypto-js` for new code (slower, mostly redundant with built-in `crypto`)

#### Security Misconfiguration (A05)

**Red Flags:**
```js
// VULNERABLE
app.use(cors({ origin: "*", credentials: true }));
res.cookie("session", token);                       // missing security flags

// SAFE
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));
res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
app.use(helmet());                                  // sets security headers
```

**Checklist:**
- [ ] Debug / development middleware (`errorhandler`, verbose stack traces) disabled in production
- [ ] CORS properly restricted (not `*` with `credentials: true`); see Express/Fastify modules
- [ ] Cookie security flags set (`httpOnly`, `secure`, `sameSite`); `domain` not over-broad
- [ ] Security headers configured (helmet for Express, `@fastify/helmet`, Next.js `headers()` config)
- [ ] `x-powered-by` removed (`app.disable("x-powered-by")`)
- [ ] `NODE_ENV=production` in production (Express disables verbose errors based on this)

#### CSRF (A01)

**Checklist:**
- [ ] State-changing operations using cookie-based auth require CSRF tokens (csurf is deprecated; use
      `@fastify/csrf-protection`, `lusca`, or hand-rolled double-submit cookie / SameSite=Strict)
- [ ] Tokens validated server-side; comparison is constant-time
- [ ] `SameSite=Lax` minimum on session cookies; `Strict` for sensitive endpoints
- [ ] API endpoints using bearer token / `Authorization` header are not CSRF-vulnerable (cookies are the issue), but
      check that they do not also accept the same auth via cookie
- [ ] CORS preflight does not bypass CSRF protection (some `cors` configs reflect Origin → CSRF)

#### Insecure Deserialization & Prototype Pollution (A08)

**Red Flags:**
```js
// VULNERABLE - eval / Function on user input
eval(req.body.expr);
new Function("return " + req.body.expr)();

// VULNERABLE - vm without isolation
const vm = require("node:vm");
vm.runInNewContext(req.body.code, ctx);             // sandbox is escapable; do not treat as secure

// VULNERABLE - YAML.load without safeLoad
yaml.load(userInput);                               // js-yaml >=4 default IS safe; but old-style yaml.load with custom schema is not
yaml.load(userInput, { schema: yaml.DEFAULT_FULL_SCHEMA });

// VULNERABLE - node-serialize / serialize-javascript with unserialize
require("node-serialize").unserialize(payload);     // RCE primitive

// VULNERABLE - prototype pollution via deep merge / object assign
_.merge({}, req.body);                              // lodash <4.17.20 vulnerable
Object.assign({}, req.body);                        // safe at top level, but assigning to an existing object's __proto__ pollutes
deepMerge(target, req.body);                        // depends on impl

// SAFE
JSON.parse(req.body);                               // safe by itself; pair with schema validation
yaml.load(userInput);                               // js-yaml ≥4 default schema is safe-only
```

**Checklist:**
- [ ] No `eval()`, `new Function(...)`, `vm.runIn*` on user input — `vm` module is NOT a security boundary
- [ ] `js-yaml` ≥4; if older, use `yaml.safeLoad` (removed in v4 because default became safe)
- [ ] No `node-serialize.unserialize`, no `funcster`, no `serialize-javascript`-decoded calls on user input
- [ ] JSON parsing paired with schema validation (zod, joi, ajv, valibot, io-ts)
- [ ] Deep-merge / clone libraries pinned to versions with prototype-pollution patches: lodash ≥4.17.21,
      `mixin-deep` ≥1.3.2, `merge-deep` ≥3.0.3, `set-value` ≥4.0.1
- [ ] Custom merge / clone functions reject keys `__proto__`, `constructor`, `prototype` (or use `Object.create(null)`
      maps for user-controlled data)
- [ ] `JSON.parse` reviver does not mutate `__proto__`
- [ ] `Object.freeze(Object.prototype)` considered for hardened deployments
- [ ] Express `query parser`: `qs` (default) parses nested query strings into objects — `?foo[__proto__][polluted]=1`
      can pollute on permissive merges. Disable with `app.set("query parser", "simple")` if not needed.

#### Insufficient Logging (A09)

**Checklist:**
- [ ] Auth events logged (login success/failure, logout, password reset, MFA enrol/use)
- [ ] Authorization failures logged
- [ ] Logs do not contain sensitive data (passwords, tokens, PII, full JWTs, session IDs)
- [ ] Log injection prevented (structured logging — pino, winston with `splat`/JSON format — not raw template literals
      with `\n` from user input)
- [ ] PII redaction in logs (pino `redact` paths, winston format) for `password`, `token`, `authorization`,
      `cookie`, `creditCard`, etc.
- [ ] Request loggers (morgan) do not log full request bodies on auth endpoints

#### Unbounded Input (Resource Exhaustion)

**Red Flags:**
```js
// VULNERABLE - no length limit (zod / yup / joi)
const Schema = z.object({ name: z.string(), description: z.string().optional() });

// SAFE
const Schema = z.object({
  name: z.string().max(255),
  description: z.string().max(2000).optional(),
});

// VULNERABLE - express body parser default limit is 100kb but easily overridden
app.use(express.json({ limit: "100mb" }));          // why?

// VULNERABLE - no body limit at all
app.use(express.json());                            // 100kb default; OK for most, but pre-auth wants tighter

// VULNERABLE - no bounds on numeric security parameter
const gracePeriodDays = Number(req.query.grace ?? 7);

// SAFE
const grace = z.coerce.number().int().min(0).max(90).parse(req.query.grace ?? 7);
```

**Checklist:**
- [ ] All string input fields have `.max(N)` (zod), `.max(N)` (yup), `.max(N)` (joi), `maxLength` (ajv)
- [ ] Numeric parameters in security contexts have `.min/.max` bounds (cert lifetimes, rate limits, timeouts)
- [ ] Database TEXT columns have length constraints (`CHECK` or `VARCHAR(N)`)
- [ ] URL fields limited to 2048 characters
- [ ] Fields typed as bare `object`, `any[]`, `Record<string, any>` have either typed sub-schemas or a body-size cap
- [ ] JSON body endpoints have a request-body size ceiling (`express.json({ limit: '...' })`,
      `fastify` `bodyLimit`, `next.config.js` `api.bodyParser.sizeLimit`)
- [ ] Pre-auth JSON endpoints (login, registration) have the tightest caps (~64 KiB)
- [ ] Standard limits: names 255, descriptions 2000, URLs 2048, enum-like 50, passwords 255, emails 320
- [ ] `qs` array limit (`parameterLimit`, `arrayLimit`) considered for `application/x-www-form-urlencoded` endpoints

#### Forwarded-Header Trust (A05)

**Red Flag:**
```js
// VULNERABLE - trusts arbitrary caller if app port is reachable directly
const host = req.headers["x-forwarded-host"] || req.headers.host;
const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;

// VULNERABLE - blanket trust
app.set("trust proxy", true);
app.set("trust proxy", "loopback,linklocal,uniquelocal");   // OK for known proxies; but `true` trusts all hops
```

`X-Forwarded-*` headers are proxy-controlled only when the app is strictly behind that proxy. If the app port is exposed
(debug, internal network, misconfigured deploy), any caller can spoof these headers.

**Checklist:**
- [ ] Every `x-forwarded-host` / `x-forwarded-proto` / `x-forwarded-for` read is either (a) non-security (logging,
      cosmetic) OR (b) gated by a trusted-proxy allowlist
- [ ] Express `trust proxy` configured to a specific number of hops or a CIDR list, not blanket `true`
- [ ] Fastify `trustProxy` set to a specific list / CIDR
- [ ] Security-relevant derivations (tenant routing, rate-limit keys, origin checks) prefer server-side sources over
      header derivation
- [ ] Container/deploy config does NOT expose the app port directly; only the reverse proxy is externally reachable

#### SSRF (A10)

**Red Flags:**
```js
// VULNERABLE - any user-controlled URL fetched
fetch(req.body.webhookUrl);
axios.get(req.body.imageUrl);
got(userUrl);
http.get(req.query.url);

// VULNERABLE - "validation" by string match (bypassable)
if (!url.includes("internal")) { fetch(url); }      // http://attacker.com#internal works

// VULNERABLE - PDF/HTML rendering of user content fetches sub-resources
puppeteer.launch().then(b => b.newPage()).then(p => p.setContent(userHtml));
// <img src="http://169.254.169.254/..."> still resolves

// SAFE - parse, allowlist scheme/host, resolve to IP, block private ranges
import { lookup } from "node:dns/promises";
import net from "node:net";

async function safeFetch(rawUrl) {
  const u = new URL(rawUrl);
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("scheme");
  const { address } = await lookup(u.hostname);
  if (isPrivateAddress(address)) throw new Error("private address");
  // NOTE: still vulnerable to DNS rebinding between this check and the actual
  // fetch. For high-value endpoints, fetch via egress proxy that re-validates.
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    return await fetch(rawUrl, { redirect: "manual", signal: ctrl.signal });
  } finally { clearTimeout(t); }
}
```

**Attack Scenarios:**
- Cloud metadata exfiltration: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS, IMDSv1),
  `http://metadata.google.internal/` (GCP), `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure,
  requires `Metadata: true` header — but webhook senders that forward headers may add it).
- Internal service access: Redis (`http://internal-redis:6379/`), unauthenticated admin endpoints, internal Elastic.
- DNS rebinding: attacker-controlled domain resolves to public IP at validation time and 169.254.169.254 at fetch time.
- Schemes beyond http: `file://`, `gopher://`, `dict://`, `ftp://`. Note: `node-fetch` and `undici` reject most of these
  by default; older `request`/`http` modules do not.

**Checklist:**
- [ ] Every `fetch`, `axios`, `got`, `node-fetch`, `undici`, `http(s).get`, `request` call on user-influenced URLs is
      wrapped in an SSRF guard
- [ ] Scheme allowlist: `http`, `https` only (no `file`, `gopher`, `dict`, `ftp`)
- [ ] Resolve hostname to IP and block private (RFC1918), loopback, link-local (`169.254/16`, IPv6 `fe80::/10`,
      `fd00::/8`), multicast, reserved
- [ ] IP literal hosts (`http://10.0.0.1/`, decimal-encoded `http://2130706433/`, IPv6 mapped `http://[::ffff:a00:1]/`)
      blocked
- [ ] `redirect: "manual"` (fetch) / `followRedirect: false` (got/axios) or redirect target re-validated
- [ ] Timeouts set on all outbound HTTP (5-10s typical) — Node's `fetch` has no default timeout; pair with
      `AbortSignal.timeout`
- [ ] For high-value flows (webhooks, image proxy, PDF rendering): outbound traffic via dedicated egress proxy with
      allowlist + IP re-validation per connection (defeats DNS rebinding)
- [ ] Header allowlist on outbound requests (do NOT forward client `Authorization`, `Cookie`, `Metadata`,
      `X-aws-ec2-metadata-token`)
- [ ] Cloud metadata endpoints explicitly blocked even if private-IP check exists (defense in depth)
- [ ] Headless-browser renderers (puppeteer, playwright) launched with `--disable-features=IsolateOrigins`,
      `--no-sandbox` reviewed; restrict navigation via `page.setRequestInterception(true)` to allowlist

#### Webhook Signature Verification

**Red Flags:**
```js
// VULNERABLE - no signature verification
app.post("/webhooks/stripe", (req, res) => {
  if (req.body.type === "invoice.paid") markPaid(req.body.data);
  res.sendStatus(200);
});

// VULNERABLE - === comparison leaks timing
const expected = crypto.createHmac("sha256", secret).update(body).digest("hex");
if (expected === req.headers["x-signature"]) process(body);

// VULNERABLE - parsed-then-reserialized JSON used for HMAC (whitespace/key-order changes break match)
app.use(express.json());                            // body parsed before HMAC verifier sees it

// SAFE
import crypto from "node:crypto";
function verify(body, sigHeader, tsHeader, secret, tolerance = 300) {
  const ts = Number(tsHeader);
  if (Math.abs(Date.now() / 1000 - ts) > tolerance) throw new Error("timestamp");
  const expected = crypto
    .createHmac("sha256", secret)
    .update(`${ts}.`).update(body).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(sigHeader);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error("sig");
}
// Mount RAW body for the webhook route: express.raw({ type: 'application/json' })
```

**Checklist:**
- [ ] Every inbound webhook (Stripe, GitHub, Slack, Twilio, SendGrid, custom) verifies signature before any side effect
- [ ] HMAC compared with `crypto.timingSafeEqual`, never `===`
- [ ] Signature input includes a timestamp; verifier enforces a tolerance window (typical 5 min)
- [ ] Replay protection: timestamp window OR nonce tracking with TTL
- [ ] Raw request body used for HMAC — Express requires `express.raw({ type: ... })` mounted on the webhook route
      *before* `express.json()`; Fastify needs `addContentTypeParser` for raw access
- [ ] Webhook secret stored in secret manager, rotatable, not committed
- [ ] Failed verifications logged with caller IP for abuse monitoring

#### Mass Assignment (A04)

**Red Flags:**
```js
// VULNERABLE - request body splatted into ORM (attacker sets isAdmin, tenantId, balance)
const user = await User.create({ ...req.body });
await User.update({ ...req.body }, { where: { id: req.user.id } });

// VULNERABLE - update from arbitrary keys
Object.assign(user, req.body);
for (const k of Object.keys(req.body)) user[k] = req.body[k];

// VULNERABLE - Mongoose findOneAndUpdate with raw body
await User.findOneAndUpdate({ _id: req.user.id }, req.body);

// SAFE - explicit allowlist (zod pick, manual destructure)
const Patch = z.object({ name: z.string().max(255), bio: z.string().max(500).optional() });
const data = Patch.parse(req.body);
await User.update(data, { where: { id: req.user.id } });
```

**Checklist:**
- [ ] No `User.create({ ...req.body })`, `Model.update(req.body)`, `Object.assign(model, req.body)` patterns
- [ ] Input validation library (zod / joi / yup / ajv / class-validator) defines client-settable fields explicitly
- [ ] Mongoose schemas: prefer `strict: true` (default) — but `findOneAndUpdate` ignores schema unless you pass
      `runValidators: true`; rely on input-layer validation, not schema-layer
- [ ] Sequelize: use `attributes` allowlist on `update` or pass a destructured object, not `req.body`
- [ ] Prisma: input types are typed but `data: req.body` still passes through; prefer destructuring or zod
- [ ] Sensitive fields (`isAdmin`, `role`, `tenantId`, `userId`, `balance`, `emailVerified`, `passwordHash`) only set by
      server-side logic, never copied from request

#### ReDoS (Regex Denial of Service)

**Red Flags:**
```js
// VULNERABLE - catastrophic backtracking on user input
/^(a+)+$/.test(userInput);
/^(\w+\s?)*$/.test(userInput);
/^([a-zA-Z0-9]+)*@/.test(userInput);                 // nested quantifiers

// VULNERABLE - user-controlled regex pattern
new RegExp(req.query.pattern).test(target);          // attacker crafts pathological regex

// VULNERABLE - common offenders
// - moment.js parsing of attacker-controlled formats (resolved in modern dayjs/luxon)
// - validator.js isFQDN/isURL on long input pre-2021
// - ms() from the `ms` package on long input (CVE)
```

**Checklist:**
- [ ] No user input as regex *pattern* (only as input to a static pattern)
- [ ] Nested quantifiers (`(a+)+`, `(a*)*`, `(.+)*`) audited; refactor to non-backtracking forms or anchor with
      possessive / atomic groups (V8 supports `(?>...)` since Node 20)
- [ ] Long input + complex regex combinations have a length cap on input before matching
- [ ] For untrusted regex evaluation, use `re2-wasm` / `node-re2` — linear time, no backtracking
- [ ] Validators (email, URL) use vetted libraries; check version for known ReDoS CVEs
- [ ] Event-loop blocking sanity check: regex against a 100KB string of `a`s should not stall the process

#### Decompression Bombs (A08)

**Red Flags:**
```js
// VULNERABLE - reads entire decompressed payload into memory
import zlib from "node:zlib";
const out = zlib.gunzipSync(req.body);                         // 10 KB compressed -> 10 GB
const Adm = require("adm-zip");
new Adm(buf).extractAllTo("/tmp/x");                           // zip slip + bomb
const tar = require("tar");
tar.x({ file, cwd: "/tmp/x" });                                // tar slip + bomb + symlink escape

// VULNERABLE - HTTP client auto-decompresses without size cap
const data = await (await fetch(url)).text();                  // gzip 1000:1 ratio -> OOM

// SAFE - cap decompressed size, stream
const out = zlib.gunzipSync(buf, { maxOutputLength: 50_000_000 });   // Node ≥21
// or stream + running total + abort over limit
```

**Checklist:**
- [ ] Decompression of user-supplied data is size-capped (`maxOutputLength` on Node ≥21, or streaming with running
      total)
- [ ] Compression-ratio sanity check on inbound gzip/deflate (reject ratios > ~100:1 for unknown content)
- [ ] `adm-zip`, `node-stream-zip`, `yauzl`, `tar` extraction loops verify each entry's resolved path stays under
      destination (zip slip / tar slip)
- [ ] `tar` symlink/hardlink members rejected or resolved (CVE-2024-28863 family)
- [ ] Image processing (sharp, jimp, gm) caps `limitInputPixels` / dimensions before decode (avoid pixel-bomb decode)
- [ ] HTTP clients fetching untrusted URLs cap response size (stream + abort over limit)

#### Race Conditions / TOCTOU

**Red Flags:**
```js
// VULNERABLE - check-then-use on filesystem (TOCTOU)
if (!fs.existsSync(path)) {
  fs.writeFileSync(path, data);                                // attacker creates symlink between check and write
}

// VULNERABLE - duplicate side effects (no idempotency)
app.post("/charge", async (req, res) => {
  await db.chargeCard(req.user.id, req.body.amount);           // double-click = double charge
});

// VULNERABLE - shared mutable module-level state across awaits
let counter = 0;
async function handler() {
  const cur = counter;
  await something();
  counter = cur + 1;                                           // lost update under concurrency
}

// SAFE - atomic open with O_EXCL
const fd = fs.openSync(path, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
fs.writeSync(fd, data); fs.closeSync(fd);

// SAFE - idempotency key
app.post("/charge", async (req, res) => {
  const key = req.headers["idempotency-key"];
  if (await seen(key)) return res.json(await priorResult(key));
  const result = await db.chargeCard(req.user.id, req.body.amount);
  await record(key, result, { ttl: 86400 });
  res.json(result);
});
```

**Checklist:**
- [ ] No filesystem `existsSync` / `stat` followed by `open` on a path that crosses a trust boundary; use
      `O_CREAT | O_EXCL` or atomic `rename`
- [ ] Money-moving / account-mutating endpoints accept and dedupe on an `Idempotency-Key`
- [ ] Async handlers do not share mutable module-level state across `await` points without a lock (`async-mutex`,
      `p-limit`, `proper-lockfile` for cross-process)
- [ ] DB-level uniqueness or `SELECT ... FOR UPDATE` (or transactional row locks) for "check uniqueness then insert"
      patterns (avoid app-layer race)
- [ ] Outbound HTTP/DB calls have explicit timeouts (no unbounded `await` in critical paths)
- [ ] Auth flows: token consumption (`UPDATE ... WHERE token=X AND used=false RETURNING ...`) atomic, not
      select-then-update

#### Redirect Validation

**Red Flag:**
```js
// VULNERABLE
res.redirect(req.query.next || "/dashboard");

// SAFE
const target = String(req.query.next ?? "/dashboard");
if (!target.startsWith("/") || target.startsWith("//") || target.includes("://")) {
  return res.redirect("/dashboard");
}
res.redirect(target);
```

**Checklist:**
- [ ] User-controlled redirect targets (next params, return URLs, RelayState) are validated
- [ ] Targets must be relative paths (start with `/`, not `//`, no `://`)
- [ ] Backslash variant rejected on Windows-aware code (`\example.com` parsed as host by some browsers)

#### Policy Consistency (Cross-cutting)

When the codebase exposes a setting or UI string that promises a security property (required MFA, session timeout,
password strength floor), trace the enforcement point and confirm it delivers the promise.

**Red Flag:**
```js
// UI says "require strong MFA" but code only checks credential exists
if (policy === "strong_mfa") return user.hasAnyMfaCredential;     // does not verify type/strength
```

**Checklist:**
- [ ] For each security policy setting, identify enforcement point(s) and confirm the check matches the promise
- [ ] Password strength thresholds applied on all paths (change, set, onboarding), not just login
- [ ] Session timeout flags honored on every session creation/regeneration path
- [ ] "Require strong MFA" gates check the actual credential type/strength, not just existence

### 3. Evidence Collection

For each vulnerability:
- Exact file and line number
- Attack scenario (how would this be exploited?)
- Exploitability (easy, moderate, difficult)
- Impact (worst case)
- Specific remediation

### 4. Report Findings

Report all findings to the user. Do not modify any code.

## Severity Guide

General floor:
- **Critical:** RCE, full database access, authentication bypass
- **High:** Data breach potential, privilege escalation, IDOR
- **Medium:** XSS, CSRF on sensitive actions, information disclosure
- **Low:** Missing headers, minor misconfigurations, theoretical risks

### Per-category severity floor

When the rubric below disagrees with intuition, use the higher severity. Authentication and authorization findings start
at **High**.

| Finding                                                       | Floor    | Promotes to                                                |
|---------------------------------------------------------------|----------|------------------------------------------------------------|
| `eval` / `Function` / `vm.run*` on untrusted input            | Critical | -                                                          |
| Command injection (`exec`/`shell:true` with user input)       | Critical | -                                                          |
| SSTI on a request-reachable path                              | Critical | -                                                          |
| SQL or NoSQL injection on authenticated endpoint              | High     | Critical if pre-auth or admin role                         |
| Prototype pollution reachable from request                    | High     | Critical if mutates auth/role objects                      |
| SSRF reaching cloud metadata or internal services             | High     | Critical if exfil already possible                         |
| Path traversal write                                          | High     | Critical if writes to executable / cron / require path     |
| Path traversal read                                           | Medium   | High if reads secrets / tokens                             |
| Auth bypass (missing middleware on a protected route)         | High     | Critical if admin-equivalent                               |
| IDOR on owned resource                                        | High     | Critical if cross-tenant                                   |
| JWT `alg=none` or algorithm confusion accepted                | Critical | -                                                          |
| TLS verification disabled (`rejectUnauthorized: false`)       | High     | Critical if used for auth tokens                           |
| Webhook signature verification missing                        | High     | -                                                          |
| Hardcoded production secret in repo                           | Critical | -                                                          |
| Hardcoded test secret confused for prod                       | Medium   | -                                                          |
| `dangerouslySetInnerHTML` / `innerHTML` with user input       | Medium   | High if reflects to other users                            |
| CSRF missing on state-changing endpoint                       | Medium   | High for money/account-mutating                            |
| Mass assignment on a model with privilege fields              | High     | Critical if `isAdmin`/`role` settable                      |
| Decompression bomb / ZIP slip on untrusted archives           | High     | -                                                          |
| ReDoS reachable from user input                               | Medium   | High if pre-auth                                           |
| Weak randomness (`Math.random`) for tokens / OTPs             | High     | -                                                          |
| Timing attack on token comparison (`===`)                     | Medium   | High if pre-auth & remotely measurable                     |
| Missing rate limit on auth / email-trigger endpoint           | Medium   | High if free-tier abuse / cost amplification               |
| CORS `origin: "*"` with `credentials: true`                   | High     | -                                                          |
| Forwarded-header trust (`trust proxy: true`) without scoping  | Medium   | High if used for tenant routing or origin check            |
| Missing security headers (HSTS, CSP, X-Frame-Options)         | Low      | Medium if app handles credentials and lacks all of them    |
| Debug mode / verbose errors enabled in production             | High     | Critical if leaks secrets / source                         |
| Open redirect                                                 | Low      | Medium if used in OAuth/SSO flow                           |
| Logging of passwords / tokens                                 | High     | -                                                          |
| Missing length cap on input field                             | Low      | Medium for pre-auth, Critical for body without overall cap |
| Insecure deserialization (`node-serialize`, `eval`)           | Critical | -                                                          |
| XXE on untrusted XML                                          | High     | Critical if file:// readable / SSRF possible               |

## Delegating to Subagents

When scope is large, delegating file clusters to `Explore` subagents is fine, but the bar for a "clean" report back is
evidence, not assertion. Reject reports that say "cluster X: clean" or "checked, OK" without specifics.

Require each cluster report to include:
- For every claim of the form "Y is not vulnerable to Z", quote the `file:line` that proves it (a parameterized query,
  an escape call, a middleware mount, a `timingSafeEqual` call, etc.).
- If the subagent found the absence of something (e.g., "no `dangerouslySetInnerHTML` without DOMPurify"), require the
  exact `grep` command it ran and a count.

If a subagent returns only narrative summaries, re-delegate with an explicit "quote the lines" instruction or do the
cluster yourself.

## Finding Format

```markdown
## [Vulnerability Type]: [Brief Description]

**Found in:** [File:line]
**Severity:** Critical/High/Medium/Low
**OWASP Category:** [e.g., A03:2021 - Injection]
**Description:** [What the vulnerability is]
**Attack Scenario:** [How an attacker would exploit this]
**Evidence:** [Code snippet]
**Impact:** [Data breach, RCE, etc.]
**Remediation:** [Specific code changes]

Example fix:
```js
// Current (vulnerable):
const q = `SELECT * FROM users WHERE email = '${email}'`;

// Fixed (parameterized):
const { rows } = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
```

---
```

## Negative Findings (Evidence Required)

A clean review is more credible when the absence of issues is *demonstrated*, not asserted. Every report includes a
"checked but clean" section. The bar is the same one applied to subagent reports: cite `file:line` evidence.

```markdown
## Categories Checked

### Triggered (see Findings above)
- A03 Injection - SQL injection in `src/api/users.ts:42`
- A02 Cryptographic Failures - `rejectUnauthorized: false` in `src/integrations/legacy.ts:18`

### Clean (with evidence)
- A01 Broken Access Control - ownership check at `src/routes/document.ts:31` (`if (doc.ownerId !== req.user.id) return res.sendStatus(404)`); IDOR-prone routes verified
- A03 Command Injection - no `child_process.exec` or `shell: true` in changed files (`grep -rn "exec(\|shell: true" src/` returned 0)
- A03 SSTI - no `Handlebars.compile` / `ejs.render` with user input (grep clean)
- A10 SSRF - outbound HTTP calls in `src/integrations/webhooks.ts:55` go through `safeFetch()` (allowlist + private-IP block)
- A07 JWT - `algorithms: ["RS256"]` pinned at `src/auth/jwt.ts:14`; `audience` and `issuer` validated

### Skipped (with reason)
- A06 Vulnerable Components - `npm audit` clean as of pre-pass; full dependency review out of scope for this PR

## Modules

### Loaded
- `express.md` (matched framework:express)
- `prisma.md` (matched dependency:@prisma/client)
- `secrets.md` (always-on)

### Skipped
- `next-api.md` - no Next.js detected
- `webauthn.md` - no WebAuthn usage detected
```

Reports without this section are incomplete. "Looks fine" / "checked, OK" is not acceptable. If a category cannot be
evidenced (no relevant code in scope), say so explicitly under Skipped with the reason.

## Module Versioning Rule

Every module declares `version: <int>` and `last_updated: YYYY-MM-DD` in frontmatter.

- **Bump `version`** when a checklist item is added, removed, or its meaning changes. Cosmetic edits (typo fixes, link
  updates) do not bump.
- **Update `last_updated`** on every merge that touches the module.
- A module with `last_updated` older than 12 months should be revisited as part of any review that loads it.

## What You Cannot Do

- No code fixes (report findings only)
- No penetration testing (code review only)
- No assumptions (verify against actual usage)

## Headless Mode

When invoked programmatically (via Agent tool), skip all interactive workflows:
- Do not ask about scope, focus, or context

### Mode A - Explicit file list

If the prompt includes a list of files:
1. Read each changed file
2. Run module discovery (list `modules/*.md`, parse frontmatter, match `applies_to` against changed files / dependency
   manifests, load matches)
3. Run the static-analyzer pre-pass scoped to the changed files (`semgrep --baseline-ref=origin/main` for diff-only,
   `eslint` on the changed files)
4. Scan for all OWASP categories relevant to the changes
5. Report findings only

### Mode B - Diff-only (no file list)

If the prompt does not specify files:
1. Run `git diff --name-only origin/main...HEAD` to enumerate changed files
2. Skip files matching `**/__tests__/**`, `**/*.test.{js,ts,tsx}`, `**/*.spec.{js,ts,tsx}`, `migrations/**`, `**/*.md`
   unless they are security-relevant configs (e.g. `.env.example`, `docker-compose.yml`, `Dockerfile`, `nginx.conf`,
   `next.config.js`)
3. Continue from step 2 of Mode A

If `git diff` returns nothing, fall back to listing files modified in the last commit (`git diff --name-only HEAD~1
HEAD`). If still empty, abort with "no changes to review."

### Reporting

Report back (for each finding):
- File and line number
- OWASP category and severity (Critical / High / Medium / Low)
- Attack scenario (how it could be exploited)
- Suggested remediation

Also report **negatives with evidence**:
- Categories checked
- Categories triggered
- Categories clean (with `file:line` citations of the safe pattern, not just "looks fine")
- Modules loaded vs skipped (with reason for skip)

If no issues found, say so explicitly. Do not edit any files.

---

## Start Here

Ask about scope, focus, and context, then proceed with systematic scanning.
