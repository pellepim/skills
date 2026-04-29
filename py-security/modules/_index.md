# Module Index

Auto-discovery is by frontmatter in each `modules/*.md` file. This file is a human-readable summary; the orchestrator
reads frontmatter directly.

### Feature / topic modules

| Module            | Triggers                                                    | Summary                                                                              |
|-------------------|-------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `email.md`        | feature:email, smtp libs (sendgrid, mailgun, anymail, etc.) | Header injection, link tokens, SPF/DKIM/DMARC, rate limits, inbound mail             |
| `file-upload.md`  | feature:file-upload, pillow, python-magic, cairosvg         | Path traversal, MIME validation, size caps, image processing exploits, safe serving  |
| `graphql.md`      | feature:graphql, strawberry, ariadne, graphene, graphql-core| Depth/complexity, introspection, batching, N+1 auth, subscriptions                   |
| `multitenancy.md` | feature:multi-tenancy, django-tenants                       | Tenant isolation, RLS, context propagation to async/jobs, leak vectors               |
| `oauth2.md`       | feature:oauth2/oidc, authlib, oauthlib, django-oauth-toolkit| PKCE, redirect URI, token storage, refresh rotation, scope, JWT                      |
| `saml.md`         | feature:saml, python3-saml, pysaml2                         | XSW, replay, audience, metadata SSRF, IdP key isolation                              |
| `secrets.md`      | always-on                                                   | Committed secrets, .env discipline, rotation, secret-manager usage                   |
| `task-queues.md`  | feature:task-queue, celery, rq, dramatiq, huey, arq         | Serializer (no pickle), arg validation, privilege boundaries, broker, schedules      |
| `webauthn.md`     | feature:webauthn/passkey, webauthn, fido2                   | UV policy, RP ID, challenge replay, credential binding, sign-count, ceremony caps    |
| `websocket.md`    | feature:websocket, channels, websockets, python-socketio    | Upgrade auth, origin, size, per-message authz, tenant isolation                      |

### Framework modules

| Module          | Triggers                                          | Summary                                                                                              |
|-----------------|---------------------------------------------------|------------------------------------------------------------------------------------------------------|
| `django.md`     | framework:django                                  | Settings hygiene, ORM raw queries, CSRF, sessions, templates, admin, middleware order                |
| `drf.md`        | framework:drf, djangorestframework                | Default permissions, viewset auth, serializer fields, IDOR, throttling, browsable API                |
| `fastapi.md`    | framework:fastapi                                 | DI auth ordering, OpenAPI exposure, response_model leaks, BackgroundTasks, CORS, async pitfalls      |
| `flask.md`      | framework:flask                                   | SECRET_KEY, signed-cookie sessions, render_template_string, blueprint auth gaps, send_file traversal |
| `sqlalchemy.md` | dependency:sqlalchemy, sqlmodel, flask-sqlalchemy | text() injection, bulk ops bypass validators, autoflush in auth, transactions                        |

## Adding a new module

1. Copy `_template.md` → `<topic>.md`.
2. Fill frontmatter (`name`, `description`, `applies_to`, `version: 1`, `last_updated`).
3. Write Risks (Red Flags + Attack Scenario + Checklist).
4. Add a row to this index.
5. No edit to `SKILL.md` required. Discovery is dynamic.
