# Backlog

Maintained by `/lead`. See `SKILL.md` for format and verbs.

---

## L-001: Node/TS backend security skill

- Status: open
- Priority: high
- Created: 2026-04-29
- Updated: 2026-04-29
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
