# Module Index

Auto-discovery is by frontmatter in each `modules/*.md` file. This file is a human-readable summary; the orchestrator
reads frontmatter directly.

### Always-on / language modules

| Module             | Triggers                                                       | Summary                                                                              |
|--------------------|----------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `secrets.md`       | always-on                                                      | Committed secrets, .env discipline, bundler `define` leakage, rotation, KMS          |
| `lang-pitfalls.md` | always-on                                                      | Prototype pollution, ReDoS, child_process, vm escape, ESM/CJS, async race            |

### Feature / topic modules

| Module             | Triggers                                                       | Summary                                                                              |
|--------------------|----------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `email.md`         | feature:email, nodemailer, sendgrid, mailgun, postmark, resend | Header injection, link tokens, SPF/DKIM/DMARC, rate limits, inbound mail             |
| `file-upload.md`   | feature:file-upload, multer, busboy, sharp, jimp, formidable   | Path traversal, MIME validation, size caps, image processing exploits, safe serving  |
| `graphql.md`       | feature:graphql, apollo-server, graphql-yoga, mercurius        | Depth/complexity, introspection, batching, N+1 auth, subscriptions                   |
| `multitenancy.md`  | feature:multi-tenancy                                          | Tenant isolation, RLS, context propagation to async/jobs, leak vectors               |
| `oauth2.md`        | feature:oauth2/oidc, openid-client, simple-oauth2              | PKCE, redirect URI, token storage, refresh rotation, scope, JWT id_token             |
| `saml.md`          | feature:saml, @node-saml/node-saml, samlify                    | XSW, replay, audience, metadata SSRF, IdP key isolation                              |
| `task-queues.md`   | feature:task-queue, bullmq, bull, agenda, bee-queue            | Arg validation, privilege boundaries, broker auth, schedules, DLQ                    |
| `templating.md`    | dependency: ejs/pug/handlebars/nunjucks/react-dom              | Auto-escape defaults, SSTI, dangerouslySetInnerHTML, SVG sanitization                |
| `webauthn.md`      | feature:webauthn/passkey, @simplewebauthn/server, fido2-lib    | UV policy, RP ID, challenge replay, credential binding, sign-count, ceremony caps    |
| `websocket.md`     | feature:websocket, ws, socket.io, @fastify/websocket           | Upgrade auth, origin, size, per-message authz, tenant isolation                      |

### Framework modules

| Module          | Triggers                                                          | Summary                                                                                              |
|-----------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| `express.md`    | framework:express                                                 | Middleware order, body limits, trust proxy, helmet, CORS, csurf deprecation, cookies                 |
| `fastify.md`    | framework:fastify                                                 | Schema-first validation, hooks, bodyLimit, trustProxy, JWT plugin, raw body for webhooks             |
| `koa.md`        | framework:koa                                                     | Middleware order, koa-bodyparser limits, koa-helmet, koa-router auth, koa-session                    |
| `nestjs.md`     | framework:nestjs, @nestjs/core                                    | Guards, ValidationPipe whitelist, interceptors, mass assignment via class-validator, RBAC            |
| `next-api.md`   | framework:next-api, next                                          | API routes, server actions, middleware, getServerSideProps, env exposure, image optimizer SSRF       |

### ORM modules

| Module          | Triggers                                                          | Summary                                                                                              |
|-----------------|-------------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| `prisma.md`     | dependency: @prisma/client, prisma                                | $queryRawUnsafe, mass assignment via data spread, multi-tenant scoping, soft delete bypass           |
| `typeorm.md`    | dependency: typeorm                                               | manager.query / QueryBuilder string concat, mass assignment via save, FindOptions injection          |
| `sequelize.md`  | dependency: sequelize                                             | sequelize.query interpolation, where operator injection, mass assignment, raw model bypass           |
| `knex.md`       | dependency: knex                                                  | knex.raw / whereRaw / orderByRaw bindings, table/column allowlists                                   |
| `mongoose.md`   | dependency: mongoose, mongodb                                     | NoSQL operator injection, $where, mass assignment via findOneAndUpdate, populate leakage             |

### Auth modules

| Module                  | Triggers                                                         | Summary                                                                                       |
|-------------------------|------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| `passport.md`           | dependency:passport                                              | Strategy verification, session serialization, OAuth state, multi-strategy account linking     |
| `next-auth.md`          | dependency:next-auth, @auth/core                                 | Provider config, session strategy, callbacks, CSRF, trustHost                                 |
| `custom-jwt.md`         | dependency:jsonwebtoken/jose, feature:jwt                        | Verify options, alg pinning, JWKS, key rotation, refresh-token rotation                       |
| `express-session.md`    | dependency:express-session                                       | Cookie flags, store, secret rotation, regenerate on login, fixation, MemoryStore in prod      |

## Adding a new module

1. Copy `_template.md` → `<topic>.md`.
2. Fill frontmatter (`name`, `description`, `applies_to`, `version: 1`, `last_updated`).
3. Write Risks (Red Flags + Attack Scenario + Checklist).
4. Add a row to this index.
5. No edit to `SKILL.md` required. Discovery is dynamic.
