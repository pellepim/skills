---
name: Prisma Security Patterns
description: $queryRawUnsafe, $executeRawUnsafe, mass assignment via data spread, multi-tenant scoping, soft delete bypass
applies_to:
  - dependency: "@prisma/client"
  - dependency: prisma
version: 1
last_updated: 2026-04-30
---

# Prisma Security Patterns

Apply when the project uses Prisma. Prisma's typed `where` / `data` arguments eliminate most SQL
injection by default; the residual risks are raw queries, mass assignment via `data: req.body`,
and missing tenant scopes.

## 1. Raw Queries

**Red Flags:**
```ts
// VULNERABLE - $queryRawUnsafe / $executeRawUnsafe with string concat
prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${email}'`);
prisma.$executeRawUnsafe("UPDATE users SET role = '" + role + "' WHERE id = " + id);

// SAFE - tagged-template variant with bound parameters
prisma.$queryRaw`SELECT * FROM users WHERE email = ${email}`;
prisma.$executeRaw`UPDATE users SET role = ${role} WHERE id = ${id}`;

// SAFE - $queryRawUnsafe with explicit parameter array
prisma.$queryRawUnsafe("SELECT * FROM users WHERE email = $1", email);
```

**Checklist:**
- [ ] No `$queryRawUnsafe(` or `$executeRawUnsafe(` with template literal interpolation or string concat
- [ ] Prefer `$queryRaw` / `$executeRaw` (tagged template) - parameters bind automatically
- [ ] Dynamic table/column names (cannot be parameterized) validated against an enum allowlist before interpolation
- [ ] LIKE patterns escape `%` and `_` if user input is the search term

## 2. Mass Assignment

**Red Flags:**
```ts
// VULNERABLE - body splatted into data
prisma.user.create({ data: req.body });                         // attacker sets `role`, `tenantId`, `emailVerified`
prisma.user.update({ where: { id: userId }, data: req.body });

// SAFE
const Schema = z.object({ name: z.string().max(255), bio: z.string().max(2000).optional() });
const data = Schema.parse(req.body);
prisma.user.update({ where: { id: userId }, data });
```

**Checklist:**
- [ ] `data: req.body` / `data: { ...req.body }` patterns flagged
- [ ] Schema validation (zod / valibot) defines client-settable fields; strips unknown keys (`.strict()` in zod for
      stricter rejection)
- [ ] Sensitive fields (`role`, `isAdmin`, `tenantId`, `userId`, `emailVerified`, `passwordHash`, `balance`) never
      copied from request body
- [ ] Nested writes (`data: { posts: { create: req.body.posts } }`) - same rules apply recursively

## 3. Multi-Tenant Scoping

**Red Flags:**
```ts
// VULNERABLE - findUnique by primary key bypasses tenant scope
prisma.document.findUnique({ where: { id: req.params.id } });   // any tenant's doc

// SAFE - compound where ensures tenant match
prisma.document.findFirst({ where: { id: req.params.id, tenantId: req.user.tenantId } });
```

**Checklist:**
- [ ] All queries on tenant-scoped models include `tenantId` in `where` (or use Prisma extensions / row-level security)
- [ ] `findUnique({ where: { id } })` audited; on tenant-scoped models prefer `findFirst({ where: { id, tenantId } })`
- [ ] Updates and deletes use `updateMany` / `deleteMany` with `tenantId` filter, OR explicit `findFirst` ownership
      check before `update`/`delete` by id
- [ ] `include` / `select` does not pull cross-tenant relations
- [ ] Prisma Client extensions / middleware that enforce tenant scope reviewed - missing on `executeRaw` paths

## 4. Soft Delete / Audit Field Bypass

**Red Flags:**
```ts
// VULNERABLE - global findMany returns soft-deleted rows when query forgets the filter
prisma.user.findMany({ where: { email } });                     // includes deletedAt != null

// SAFE - middleware or extension applies the filter, OR explicit on every query
prisma.user.findMany({ where: { email, deletedAt: null } });
```

**Checklist:**
- [ ] Soft-delete filter applied consistently (extension, middleware, or query helper)
- [ ] Audit fields (`createdBy`, `updatedBy`) set server-side from `req.user.id`, never from request body

## 5. Connection / Pool Settings

**Checklist:**
- [ ] `DATABASE_URL` not committed; loaded from secret store
- [ ] Connection pool size bounded (`?connection_limit=` in URL); prevents one tenant exhausting the pool
- [ ] `?sslmode=require` (Postgres) or equivalent set; do not allow plaintext DB connections

## 6. Logging

**Checklist:**
- [ ] Prisma `log: ['query', 'info', 'warn', 'error']` does NOT log query parameters in production (parameters can
      contain PII / tokens) - use `'info'`/`'warn'`/`'error'` only, or redact via a custom log handler
- [ ] No raw query bodies logged at `info` level

## 7. Migrations

**Checklist:**
- [ ] `prisma migrate deploy` (not `migrate dev`) used in production deploy
- [ ] Migrations reviewed for accidental data exposure (e.g. dropping a NOT NULL constraint that backed a security
      assumption)

## References

- Prisma security: https://www.prisma.io/docs/orm/prisma-client/queries/raw-database-access/raw-queries
