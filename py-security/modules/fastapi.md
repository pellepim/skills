---
name: FastAPI Security Patterns
description: DI auth ordering, OpenAPI exposure, response_model leaks, BackgroundTasks, CORS placement
applies_to:
  - framework: fastapi
  - dependency: fastapi
version: 1
last_updated: 2026-04-29
---

# FastAPI Security Patterns

Apply when the project uses FastAPI. Starlette-only projects share most of these.

## 1. Authentication via Dependencies

**Red Flags:**
```python
# VULNERABLE - dependency declared but not invoked on the route
def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    return decode(token)

@app.get("/admin")
def admin():  # forgot to add `user = Depends(get_current_user)` — endpoint is public
    return secrets

# VULNERABLE - auth dependency bypassed via path inclusion order
app.include_router(public_router)
app.include_router(admin_router, dependencies=[Depends(get_current_user)])
# but admin_router internally re-declares routes without the dep...
```

**Checklist:**
- [ ] Every protected endpoint either declares `Depends(get_current_user)` directly or is included under a router with
      `dependencies=[...]`
- [ ] Router-level `dependencies` not overridden by a sub-router that omits them
- [ ] `Security(...)` (or `Depends(...)` for non-OAuth) used consistently; do not mix manual header parsing with the
      framework's auth
- [ ] Admin / role-restricted endpoints use a separate dependency (`Depends(require_admin)`) layered on top, not an `if
      user.is_admin` inside the handler (easy to forget)
- [ ] `dependency_overrides` only used in tests, never in production code paths

## 2. OpenAPI / Docs Exposure

**Red Flags:**
```python
# VULNERABLE - docs exposed in production reveal internal endpoints
app = FastAPI()  # /docs, /redoc, /openapi.json all enabled by default

# SAFE - disable in prod or auth-gate
app = FastAPI(
    docs_url=None if settings.ENV == "prod" else "/docs",
    redoc_url=None if settings.ENV == "prod" else "/redoc",
    openapi_url=None if settings.ENV == "prod" else "/openapi.json",
)
```

**Checklist:**
- [ ] `/docs`, `/redoc`, `/openapi.json` disabled or auth-gated in production
- [ ] Internal-only routes use `include_in_schema=False`
- [ ] Error responses do not include the full schema name on validation failure (FastAPI default leaks internal model
      names — acceptable, but be aware)

## 3. response_model — Information Leakage

**Red Flags:**
```python
# VULNERABLE - returns the full ORM object, including hashed_password, internal_id, audit_log
@app.get("/users/{id}")
def get_user(id: int) -> User:    # User is the ORM model
    return db.get_user(id)

# SAFE - explicit response model strips fields
class UserPublic(BaseModel):
    id: int
    name: str
    avatar_url: str | None
    model_config = ConfigDict(from_attributes=True)

@app.get("/users/{id}", response_model=UserPublic)
def get_user(id: int):
    return db.get_user(id)
```

**Checklist:**
- [ ] Endpoints declare `response_model=` (Pydantic v2: also valid as return type annotation)
- [ ] Output models distinct from input/ORM models (no shared `User` for `request body` and `response`)
- [ ] Sensitive fields (`hashed_password`, `password_reset_token`, `mfa_secret`, `internal_*`) explicitly excluded
- [ ] `response_model_exclude_none=True` considered for partial-update responses (avoids leaking absent fields with
      `null`)

## 4. Background Tasks & Privilege

**Red Flags:**
```python
# VULNERABLE - background task runs in the same process with the request user's token
@app.post("/export")
def export(user = Depends(get_current_user), bg: BackgroundTasks):
    bg.add_task(run_long_export, user_id=user.id, token=user.token)
    # task continues after request returns; if it makes outbound calls with `user.token`,
    # the token may have been revoked or the request context cleaned up.
```

**Checklist:**
- [ ] Background tasks do not assume request-scoped state (DB session, request user) is still valid
- [ ] Long-running work routes through a real task queue (Celery, Arq, RQ) not `BackgroundTasks` (see `task-queues.md`)
- [ ] Tenant/user context passed explicitly as task arguments
- [ ] Background-task exceptions logged (FastAPI swallows them by default)

## 5. CORS

**Red Flags:**
```python
# VULNERABLE - permissive CORS with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,   # spec violation, but some browsers honor with reflected origin
)

# VULNERABLE - reflects any Origin
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
)
```

**Checklist:**
- [ ] `allow_origins` is an explicit list of `https://...` origins; never `["*"]` with `allow_credentials=True`
- [ ] `allow_origin_regex` audited; no `.*` patterns
- [ ] CORS middleware position: added before auth middleware so preflights succeed; but ensure preflight handler is not
      a CSRF bypass for cookie-authed endpoints
- [ ] `allow_methods` and `allow_headers` not blanket `["*"]` for credentialed endpoints
- [ ] `expose_headers` minimal (avoid leaking internal headers like `X-Request-Id` to other origins if not needed)

## 6. Form vs JSON Body Caps

**Red Flags:**
```python
# VULNERABLE - reads entire body before any size check
@app.post("/upload")
async def upload(req: Request):
    data = await req.body()   # 10 GB? Sure.
```

**Checklist:**
- [ ] Reverse proxy (nginx `client_max_body_size`, Caddy `request_body max_size`) caps body size before FastAPI sees it
- [ ] `Form()`, `Query()`, `Path()` parameters have `max_length` for strings
- [ ] Pre-auth endpoints (login, register, password reset) have the tightest body caps (~128 KiB)
- [ ] File uploads use `UploadFile` and stream; do not call `await file.read()` without a size guard

## 7. Trusted Hosts / Forwarded Headers

**Red Flags:**
```python
# VULNERABLE - trusts X-Forwarded-* unconditionally
app.add_middleware(ProxyHeadersMiddleware, trusted_hosts="*")
```

**Checklist:**
- [ ] `TrustedHostMiddleware` configured with explicit `allowed_hosts` (no `["*"]`)
- [ ] `ProxyHeadersMiddleware` (Uvicorn) `forwarded_allow_ips` set to the proxy IP, not `"*"`, when behind a proxy
- [ ] App port not directly exposed to the internet (only the proxy)
- [ ] See SKILL.md "Forwarded-Header Trust" for the broader pattern

## 8. Async Handlers

**Checklist:**
- [ ] No shared mutable Python state across `await` points (see SKILL.md "Race / TOCTOU")
- [ ] All outbound HTTP / DB calls have explicit timeouts
- [ ] Blocking I/O (CPU-bound work, sync DB drivers) wrapped in `run_in_threadpool` or pushed to a worker — long
      blocking handlers DoS the event loop

## References

- FastAPI security docs: https://fastapi.tiangolo.com/tutorial/security/
- Starlette CORS: https://www.starlette.io/middleware/#corsmiddleware
