---
name: Multi-Tenancy Security Patterns
description: Tenant isolation, RLS, context propagation to async/jobs, leak vectors, scoped IDs
applies_to:
  - feature: multi-tenancy
version: 1
last_updated: 2026-04-30
---

# Multi-Tenancy Security Patterns

Apply when the application serves multiple tenants from a shared codebase / database. Most issues
are missed scope filters and context loss across async boundaries.

## 1. Tenant Scoping at the ORM Layer

**Red Flags:**
```ts
// VULNERABLE - findById bypasses tenant scope
const doc = await prisma.document.findUnique({ where: { id: req.params.id } });

// VULNERABLE - update by primary key
await prisma.document.update({ where: { id }, data });

// SAFE
const doc = await prisma.document.findFirst({ where: { id, tenantId: req.user.tenantId } });
await prisma.document.updateMany({ where: { id, tenantId: req.user.tenantId }, data });
```

**Checklist:**
- [ ] Every query on tenant-scoped models filters by `tenantId` (or equivalent scope key)
- [ ] `findUnique`/`findById` on tenant-scoped models replaced with `findFirst({ where: { id, tenantId } })`
- [ ] `update`/`delete` by primary key replaced with `updateMany`/`deleteMany` with tenant filter, OR preceded by
      explicit `findFirst` ownership check
- [ ] Bulk operations (`createMany`, `deleteMany`) audited - tenant scope on every where-clause

## 2. Database-Level Enforcement

**Checklist:**
- [ ] PostgreSQL Row-Level Security (RLS) policies applied to tenant tables; app sets `SET app.current_tenant` per
      transaction; policies reject access when unset
- [ ] OR: schema-per-tenant with connection routing - search_path set at connection acquisition time, not per query
- [ ] OR: database-per-tenant - strongest isolation, highest operational cost
- [ ] Background jobs / migrations that run as superuser bypass RLS - audited separately

## 3. Context Propagation

**Red Flags:**
```js
// VULNERABLE - tenant context lost across setTimeout / Promise / queue
async function handler(req, res) {
  setTimeout(() => sendEmail(req.user.tenantId, ...), 1000);    // tenantId captured but easy to forget
  await queue.add("export", { ... });                           // tenantId not passed; worker uses default scope
}
```

**Checklist:**
- [ ] Tenant ID passed explicitly as job argument; never inferred from a global / module variable in the worker
- [ ] AsyncLocalStorage used for in-process context carrying (Node `node:async_hooks`); verified to survive across
      `await`, `setTimeout`, and queue boundaries
- [ ] Cross-process boundary (queue, RPC, webhook) re-asserts tenant from the message payload, not from server state
- [ ] Logs include tenant ID on every line (pino `mixin`, winston format)

## 4. Cross-Tenant Resource Identifiers

**Red Flags:**
```js
// VULNERABLE - sequential integer IDs allow guessing across tenants
GET /api/documents/123                                          // user could try 124, 125, ...

// VULNERABLE - tenant-aware path but no enforcement
GET /api/tenants/:tenantId/documents/:id
// handler trusts :tenantId param - attacker swaps to victim tenant
```

**Checklist:**
- [ ] Resource IDs are unguessable (UUID, ULID, or random base32 ≥10 chars) - reduces blast radius of IDOR
- [ ] `:tenantId` in URL paths IGNORED for authorization; tenant always derived from authenticated session
- [ ] OR: tenant in URL is verified to match session tenant (defense in depth, but session source is canonical)

## 5. File / Object Storage

**Checklist:**
- [ ] S3 / GCS keys prefixed with tenant ID; IAM policies enforce per-tenant access (where the architecture supports
      per-tenant credentials)
- [ ] Presigned URLs generated server-side after authorization; URL TTL bounded
- [ ] No global "public" bucket for user uploads

## 6. Cache Keys

**Red Flags:**
```js
// VULNERABLE - cache key without tenant
cache.set(`user:${userId}`, data);                              // userId from a different tenant might collide
cache.set(`document:${docId}`, data);                           // doc IDs across tenants might collide if non-unique

// SAFE
cache.set(`t:${tenantId}:user:${userId}`, data);
```

**Checklist:**
- [ ] Cache keys (Redis, in-memory, CDN) include tenant ID
- [ ] Cache invalidation scoped per tenant (one tenant's purge does not affect another)
- [ ] Public/non-tenant data in a separate keyspace

## 7. Subdomain / Custom Domain Routing

**Checklist:**
- [ ] Tenant identified from session cookie (or `Host`/subdomain) - NOT from a body field
- [ ] Custom-domain support: ownership verified via DNS challenge before activation; CNAME mapping audited per tenant
- [ ] Cookie `domain` attribute reviewed - a tenant subdomain cookie should NOT be sent to other tenant subdomains
      (use `__Host-` prefix or per-subdomain cookies)
- [ ] CSP / CORS policies do not inadvertently allow cross-tenant origins

## 8. Reports / Aggregations

**Checklist:**
- [ ] Aggregation queries (analytics, dashboards) filter by tenant in the same way; no global SUM that aggregates
      across tenants accidentally
- [ ] Cross-tenant reports (admin/billing) explicitly auth-gated to internal staff

## 9. Tenant Onboarding / Offboarding

**Checklist:**
- [ ] New-tenant provisioning isolates resources by default (new bucket prefix, new RLS policy applied)
- [ ] Tenant deletion: cascading deletes audited; orphaned resources flagged
- [ ] Data export on offboarding scoped strictly to that tenant

## References

- PostgreSQL RLS: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- AsyncLocalStorage: https://nodejs.org/api/async_context.html
