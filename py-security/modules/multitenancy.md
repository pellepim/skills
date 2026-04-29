---
name: Multi-Tenancy Security Patterns
description: Tenant isolation models, RLS, tenant context propagation to async/jobs, cross-tenant leak vectors
applies_to:
  - feature: multi-tenancy
  - dependency: django-tenants
  - dependency: sqlalchemy-multi-tenant
version: 1
last_updated: 2026-04-29
---

# Multi-Tenancy Security Patterns

Optional module for the `/security` skill. Apply when the project serves multiple tenants from a shared infrastructure
(shared DB, schema-per-tenant, or DB-per-tenant).

## 1. Tenant Isolation Model

Identify which model the project uses, then apply the corresponding checks:

| Model                                 | Isolation | Risk Profile                              |
|---------------------------------------|-----------|-------------------------------------------|
| Shared DB + shared schema (row-level) | Lowest    | Every query must filter by tenant_id      |
| Shared DB + schema-per-tenant         | Medium    | Schema search path must be set correctly  |
| Database-per-tenant                   | Highest   | Connection routing must be correct        |

## 2. Row-Level Isolation (Shared Schema)

**Red Flags:**
```python
# VULNERABLE - no tenant scoping
def get_users():
    return db.execute("SELECT * FROM users")

# VULNERABLE - tenant_id from user input, not session
def get_users(request):
    tenant_id = request.args.get("tenant_id")  # Attacker controls this
    return db.execute("SELECT * FROM users WHERE tenant_id = %s", (tenant_id,))

# SAFE - tenant_id from authenticated session
def get_users(current_user):
    return db.execute("SELECT * FROM users WHERE tenant_id = %s",
                      (current_user.tenant_id,))
```

**Checklist:**
- [ ] Every query on tenant-scoped tables includes `tenant_id` in `WHERE` clause
- [ ] `tenant_id` sourced from authenticated session/token, never from request parameters
- [ ] Database-level RLS policies enforced (not just application-level filtering)
- [ ] RLS cannot be bypassed by the application's DB role (`SET ROLE` or `SECURITY DEFINER` usage audited)
- [ ] Cross-tenant queries (admin, background jobs) use an explicit bypass mechanism that is auditable
- [ ] Foreign key relationships include `tenant_id` (prevent cross-tenant references)
- [ ] Unique constraints include `tenant_id` where appropriate (email unique per tenant, not globally)

## 3. Schema-Per-Tenant

**Checklist:**
- [ ] Schema search path set at connection/transaction start, not cached across requests
- [ ] Schema name derived from authenticated session, not request input
- [ ] Schema name sanitized if used in dynamic SQL (prevent SQL injection via tenant name)
- [ ] Shared/public schema access controlled (no tenant data in public schema)
- [ ] Migrations applied consistently across all tenant schemas

## 4. Database-Per-Tenant

**Checklist:**
- [ ] Connection string lookup based on authenticated tenant, not request parameter
- [ ] Connection pool per tenant (no connection reuse across tenants)
- [ ] Default/fallback database does not contain tenant data
- [ ] Database credentials differ per tenant (or use a proxy with tenant routing)

## 5. Tenant Context Propagation

**Red Flags:**
```python
# VULNERABLE - tenant context lost in async/background operations
@app.route("/export")
def start_export(current_user):
    task = export_data.delay()  # Where did tenant_id go?
    return {"task_id": task.id}

@celery.task
def export_data():
    data = db.get_all_data()  # Cross-tenant leak
```

**Checklist:**
- [ ] Tenant context explicitly passed to background jobs (not inherited from thread-local/request)
- [ ] Async tasks include `tenant_id` as a required parameter
- [ ] Middleware sets tenant context early in request lifecycle
- [ ] Tenant context cleared after request completes (no bleed between requests)
- [ ] Signal/event handlers propagate tenant context to subscribers

## 6. Cross-Tenant Data Leaks

**Common leak vectors:**
- Caching without tenant-scoped keys
- Search/full-text indexes without tenant filtering
- File storage without tenant-prefixed paths
- Logging that includes data from multiple tenants
- Error messages that reference other tenants' data
- Aggregation queries that span tenants
- Shared queues or pub/sub channels

**Checklist:**
- [ ] Cache keys include tenant_id prefix (`tenant:{id}:user:{uid}`, not `user:{uid}`)
- [ ] Search indexes scoped by tenant (filter, not post-filter)
- [ ] File/blob storage paths include tenant isolation (`/tenants/{id}/uploads/`, not `/uploads/`)
- [ ] Logs do not mix tenant data in ways that could leak through log access
- [ ] Error responses never reference resources from other tenants
- [ ] Pagination cursors do not encode cross-tenant state

## 7. Resource Exhaustion Across Tenants

**Checklist:**
- [ ] Per-tenant rate limiting (one tenant cannot DoS others)
- [ ] Per-tenant storage quotas (disk, blob, database rows)
- [ ] Per-tenant connection pool limits (one tenant cannot exhaust DB connections)
- [ ] Per-tenant compute limits on expensive operations (reports, exports, bulk operations)
- [ ] Shared infrastructure has capacity for peak usage across tenants (or queuing/backpressure)
- [ ] Background job queues isolated per tenant or fairly scheduled (one tenant's backlog does not block others)

## 8. Tenant Administration

**Red Flags:**
```python
# VULNERABLE - super admin can access any tenant without audit
def admin_view_tenant(admin_user, tenant_id):
    return db.execute("SELECT * FROM users WHERE tenant_id = %s", (tenant_id,))
    # No audit trail of cross-tenant access
```

**Checklist:**
- [ ] Cross-tenant admin access audited (who accessed which tenant, when)
- [ ] Tenant admin cannot escalate to platform admin
- [ ] Tenant deletion is soft-delete with retention period (not immediate purge)
- [ ] Tenant data export available for compliance (GDPR, data portability)
- [ ] Tenant configuration changes audited

## 9. Subdomain / Domain Routing

**Checklist:**
- [ ] Tenant resolved from subdomain/domain using server-side lookup (not header trust)
- [ ] Unknown subdomains return 404, not a default tenant's data
- [ ] Tenant routing checked before authentication (prevents auth to wrong tenant)
- [ ] SSL/TLS certificates cover tenant subdomains (wildcard or per-tenant)
- [ ] DNS rebinding protection if tenant-specific domains are supported
