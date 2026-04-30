---
name: TypeORM Security Patterns
description: query() / createQueryBuilder string concat, mass assignment via save, find by FindOptionsWhere injection
applies_to:
  - dependency: typeorm
version: 1
last_updated: 2026-04-30
---

# TypeORM Security Patterns

Apply when the project uses TypeORM. Highest-risk patterns are `manager.query` with interpolation
and QueryBuilder string-concatenated `where` clauses.

## 1. Raw / QueryBuilder

**Red Flags:**
```ts
// VULNERABLE - manager.query with template literal
manager.query(`SELECT * FROM users WHERE email = '${email}'`);

// VULNERABLE - createQueryBuilder where string concat
repo.createQueryBuilder("u").where("u.email = '" + email + "'").getOne();
repo.createQueryBuilder("u").where(`u.email = '${email}'`).getOne();

// VULNERABLE - orderBy with user input (column name)
qb.orderBy(req.query.sort);                                     // no allowlist

// SAFE - parameterized
manager.query("SELECT * FROM users WHERE email = $1", [email]);
repo.createQueryBuilder("u").where("u.email = :email", { email }).getOne();
qb.orderBy(ALLOWED_SORTS[req.query.sort] ?? "u.createdAt", "DESC");
```

**Checklist:**
- [ ] No template literals or `+` concat in `manager.query(...)`, `Repository.query(...)`,
      `createQueryBuilder().where(...)`, `.andWhere(...)`, `.orderBy(...)`, `.having(...)`
- [ ] `where("col = :name", { name: value })` uses named parameters
- [ ] Dynamic column names (`orderBy`, `select`) validated against allowlist
- [ ] `IN (:...ids)` uses spread placeholder, not string-joined values

## 2. Mass Assignment

**Red Flags:**
```ts
// VULNERABLE - save spreads request body into entity
const user = repo.create({ ...req.body });
await repo.save(user);

// VULNERABLE - update with arbitrary keys
await repo.update({ id: req.user.id }, req.body);

// SAFE
const Patch = z.object({ name: z.string().max(255), bio: z.string().max(2000).optional() });
const data = Patch.parse(req.body);
await repo.update({ id: req.user.id }, data);
```

**Checklist:**
- [ ] No `repo.create({ ...req.body })`, `repo.save({ ...req.body, id })`, `repo.update(where, req.body)` patterns
- [ ] Input validation (class-validator, zod) defines client-settable fields explicitly
- [ ] `@Column({ select: false })` on sensitive fields (`passwordHash`) so default `find` does not return them - then
      explicitly `addSelect` only where needed

## 3. find / FindOptionsWhere Injection

**Red Flags:**
```ts
// VULNERABLE - object body splatted into where; attacker can inject MoreThan / Not / IsNull operators
// via TypeORM's symbol-based operator detection (varies by version)
repo.findOne({ where: req.query });
```

**Checklist:**
- [ ] `findOne({ where: req.query })` / `find({ where: req.body })` patterns flagged
- [ ] User input cast to primitive types before being placed in `where`; use schema validation
- [ ] No raw object spread of request data into `where`, `relations`, `select`, or `order`

## 4. Multi-Tenant Scoping

**Red Flags:**
```ts
// VULNERABLE - findOneBy on PK ignores tenant
repo.findOneBy({ id: req.params.id });

// SAFE
repo.findOneBy({ id: req.params.id, tenantId: req.user.tenantId });
```

**Checklist:**
- [ ] All queries on tenant-scoped entities include `tenantId` in `where`
- [ ] Subscribers / event listeners that mutate other entities re-apply tenant scope
- [ ] Prefer entity subscribers or query hooks that fail-closed if `tenantId` missing

## 5. Logging / Connection

**Checklist:**
- [ ] `logging: false` (or scoped to errors only) in production - avoids logging parameter values
- [ ] `synchronize: false` in production (must be off; `true` drops/recreates schema)
- [ ] `migrationsRun` controlled via deploy pipeline, not at app startup with admin-credential
- [ ] SSL enforced on database connection

## 6. Soft Delete

**Checklist:**
- [ ] If using `@DeleteDateColumn`, all custom queries that bypass `softDelete` (raw `DELETE`, `delete()`) audited
- [ ] `withDeleted: true` used only for admin / restore flows; default queries exclude soft-deleted

## References

- TypeORM security: https://typeorm.io/find-options
