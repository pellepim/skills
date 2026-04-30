# Backlog

Maintained by `/lead`. See `SKILL.md` for format and verbs.

---

## L-001: Node/TS backend security skill

- Status: done
- Priority: high
- Created: 2026-04-29
- Updated: 2026-04-30
- Tags: security, node, typescript
- Owner: unassigned

Mirror of `py-security` for Node/JS/TS backends. Covers Express, Fastify, NestJS, Koa,
Next.js API routes. Highest payoff first because Node has the largest active threat
surface and weakest static tooling.

### Plan
- Copy py-security skeleton (SKILL.md, tools/, modules/, _template, _index).
- Tools pre-pass: `npm audit` / `osv-scanner`, ESLint security plugins, Semgrep, gitleaks.
- Framework modules: express, fastify, nestjs, koa, next-api.
- ORM modules: prisma, typeorm, sequelize, knex, mongoose.
- Auth modules: passport, next-auth, custom-jwt, express-session.
- Lang-specific: prototype pollution, regex DoS, child_process, vm escape, async race in
  middleware, ESM/CJS confusion.
- Templating: ejs, pug, handlebars, react SSR (dangerouslySetInnerHTML).

### Notes
- 2026-04-29: Created. Suggested order Node first, then .NET, then Java.
- 2026-04-30: Done. Skill at `node-security/` mirrors `py-security/` with
  framework modules (express, fastify, nestjs, koa, next-api), ORM modules
  (prisma, typeorm, sequelize, knex, mongoose), auth modules (passport,
  next-auth, custom-jwt, express-session), feature modules (file-upload,
  graphql, websocket, oauth2, saml, webauthn, email, multitenancy,
  task-queues, templating), plus always-on `secrets.md` and
  `lang-pitfalls.md` (proto pollution, ReDoS, child_process, vm escape,
  ESM/CJS).

---

## L-002: .NET / C# backend security skill

- Status: open
- Priority: medium
- Created: 2026-04-29
- Updated: 2026-04-29
- Tags: security, dotnet, csharp
- Owner: unassigned

Mirror of `py-security` for .NET backends. Covers ASP.NET Core MVC and minimal APIs,
EF Core, Dapper, SignalR, Identity, Hangfire/Quartz.

### Plan
- Copy py-security skeleton.
- Tools pre-pass: Roslyn analyzers, `security-code-scan`, `dotnet list package
  --vulnerable`, Semgrep, gitleaks.
- Framework modules: aspnet-mvc, aspnet-minimal-api, signalr.
- ORM modules: efcore, dapper.
- Auth modules: aspnet-identity, jwt-bearer, cookie-auth, oidc-handlers.
- Templating: razor (`Html.Raw` review, encoder defaults).
- Serialization: `BinaryFormatter`, `JavaScriptSerializer`, Newtonsoft `TypeNameHandling`.
- Lang-specific: model binding overposting, antiforgery, LINQ string interpolation.

### Notes
- 2026-04-29: Created. Mature ecosystem, fewer framework variants than Java.

---

## L-003: Java backend security skill

- Status: open
- Priority: medium
- Created: 2026-04-29
- Updated: 2026-04-29
- Tags: security, java, jvm
- Owner: unassigned

Mirror of `py-security` for Java/JVM backends. Largest surface of the three. Spring alone
likely needs separate sub-modules.

### Plan
- Copy py-security skeleton.
- Tools pre-pass: SpotBugs + `find-sec-bugs`, OWASP `dependency-check` or Snyk, Semgrep,
  gitleaks.
- Framework modules: spring-mvc, spring-security, spring-data, jakarta-ee, jaxrs,
  micronaut, quarkus, struts.
- ORM modules: jpa-hibernate (HQL injection focus).
- Templating: jsp, thymeleaf, freemarker, velocity (autoescape + SSTI).
- Serialization: java native, jackson polymorphic, snakeyaml, xstream, xxe in jaxb/dom.
- Lang-specific: SpEL/OGNL injection, reflection, `Runtime.exec`, classloader, expression
  languages.

### Notes
- 2026-04-29: Created. Longest tail. Save for last.

---

## L-004: py-security lang-pitfalls always-on module

- Status: open
- Priority: medium
- Created: 2026-04-30
- Updated: 2026-04-30
- Tags: security, python, refactor
- Owner: unassigned

Extract Python language footguns from SKILL.md into a dedicated always-on module mirroring
node-security's `lang-pitfalls.md`. Cleaner separation, easier to evolve, surfaces pattern in
module index.

### Plan
- New `py-security/modules/lang-pitfalls.md` with `applies_to: [any]`.
- Move/condense from SKILL.md: pickle / `__reduce__`, eval/exec on user input.
- Add coverage not currently in SKILL.md: GIL false-confidence on shared state, sync/async
  mixing (sync DB drivers in async handlers), contextvars loss across `await`, monkey-patching,
  format-string injection (`"{}".format(user_input)` reading attrs), decimal-vs-float for
  money, dict-ordering assumptions, signal handlers in multi-threaded servers.
- Trim SKILL.md to a one-line pointer where overlap.

---

## L-005: py-security NoSQL / Mongo module

- Status: open
- Priority: medium
- Created: 2026-04-30
- Updated: 2026-04-30
- Tags: security, python, mongodb
- Owner: unassigned

Mongo operator-injection coverage missing from py-security; node-security has it via
`mongoose.md`. Python apps with `pymongo`/`motor`/`mongoengine`/`beanie` carry the same risks.

### Plan
- New `py-security/modules/pymongo.md` with `applies_to: dependency:[pymongo, motor,
  mongoengine, beanie]`.
- Operator injection (`$where`, `$ne`, `$gt` via dict spread).
- Mass assignment via `update_one(filter, {"$set": dict(req.body)})`.
- ObjectId validation before query.
- Multi-tenant scope on `find_one(_id=...)`.
- Aggregation pipeline operator audit.

---

## L-006: py-security custom-jwt module

- Status: open
- Priority: medium
- Created: 2026-04-30
- Updated: 2026-04-30
- Tags: security, python, jwt
- Owner: unassigned

JWT coverage currently inline in SKILL.md. Promote to module so PyJWT / python-jose / authlib
projects auto-load it, parallel to node-security's `custom-jwt.md`.

### Plan
- New `py-security/modules/custom-jwt.md`, `applies_to: dependency:[PyJWT, python-jose,
  authlib]` and `feature: jwt`.
- Algorithms pinned, none rejected, HS/RS confusion.
- aud / iss / nonce validation.
- JWKS via `iss`-derived URL = SSRF risk.
- `kid` allowlist; HTTPS-pinned JWKS; cache TTL.
- Refresh-token rotation, reuse detection, family revocation.
- Session-token-as-JWT antipattern (revocation list / short TTL).

---

## L-007: py-security templating module

- Status: open
- Priority: low
- Created: 2026-04-30
- Updated: 2026-04-30
- Tags: security, python, templating
- Owner: unassigned

Jinja2 / Mako / Chameleon / Django template auto-escape rules currently scattered across
SKILL.md and framework modules. Consolidate.

### Plan
- New `py-security/modules/templating.md`, `applies_to: dependency:[jinja2, mako, chameleon]`
  and `framework:[django]`.
- Per-engine: autoescape default, `|safe` / `mark_safe` / `Markup()` audit, SSTI patterns
  (`Template(user_input)`, `render_template_string`), SVG sanitization, email-template
  injection, `format_html`.
- React-SSR equivalent: HTMX swap returning rendered ORM partial leaks fields - link to
  framework modules.

---

## L-008: py-security framework-auth modules

- Status: open
- Priority: low
- Created: 2026-04-30
- Updated: 2026-04-30
- Tags: security, python, auth
- Owner: unassigned

py-security has feature-level `oauth2.md` / `saml.md` but no framework-auth modules. Mirror
node-security's per-library auth coverage (`passport.md`, `next-auth.md`).

### Plan
- `django-allauth.md`: signup adapter, social-account email-verified linking, account-existence
  enumeration.
- `authlib.md`: client + provider patterns, token endpoint auth, ID token validation.
- `python-social-auth.md`: pipeline ordering, association vs disconnection.
- `flask-login.md`: session loader, fresh-login, remember-me cookie.

---

## L-009: py-security secrets bundler-leakage section

- Status: open
- Priority: low
- Created: 2026-04-30
- Updated: 2026-04-30
- Tags: security, python, secrets
- Owner: unassigned

node-security `secrets.md` flagged Vite `define` / Next env inlining. Python equivalents
missing from `py-security/modules/secrets.md`.

### Plan
- Add section: secrets baked into wheels (`MANIFEST.in` over-inclusive).
- Docker `ARG SECRET=...` visible in `docker history`; switch to BuildKit `--mount=type=secret`.
- Streamlit Cloud / HuggingFace Spaces secrets exposure model.
- PyInstaller / Nuitka bundles - run gitleaks against build artifacts before publish.
- `pip install` of editable local package picks up uncommitted `.env` if shipped in package
  data.
