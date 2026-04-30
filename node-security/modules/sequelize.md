---
name: Sequelize Security Patterns
description: sequelize.query string interpolation, where operator injection, mass assignment via update, raw model bypass
applies_to:
  - dependency: sequelize
version: 1
last_updated: 2026-04-30
---

# Sequelize Security Patterns

Apply when the project uses Sequelize.

## 1. sequelize.query / Literal

**Red Flags:**
```js
// VULNERABLE - template literal in raw query
sequelize.query(`SELECT * FROM users WHERE email = '${email}'`);

// VULNERABLE - sequelize.literal with user input
{ where: sequelize.literal(`email = '${email}'`) }

// VULNERABLE - sequelize.fn with user-controlled function name
sequelize.fn(req.query.fn, sequelize.col("name"));

// SAFE
sequelize.query("SELECT * FROM users WHERE email = :email", {
  replacements: { email },
  type: QueryTypes.SELECT,
});
sequelize.query("SELECT * FROM users WHERE email = $1", { bind: [email], type: QueryTypes.SELECT });
```

**Checklist:**
- [ ] No template literals or `+` concat in `sequelize.query(...)`
- [ ] Use `replacements` (Sequelize escapes) or `bind` (driver-level binding) - not raw interpolation
- [ ] `sequelize.literal(...)` flagged on every use; inputs must be from a static allowlist
- [ ] Dynamic column / table names validated against allowlist before passing to literal/col/fn

## 2. Operator Injection

**Red Flags:**
```js
// VULNERABLE - body splatted into where; attacker can inject Op.ne, Op.gt
User.findOne({ where: { ...req.body } });
User.findOne({ where: req.body });
// attacker posts {"password": {"[Op.ne]": null}} (older Sequelize) or {"password":{"$ne": null}}
// (operatorsAliases enabled - DEPRECATED but possible in legacy code)
```

**Checklist:**
- [ ] `operatorsAliases: false` (default in modern Sequelize) - never `operatorsAliases: true` or a custom alias map
      that exposes operators by string key
- [ ] Inputs cast to primitives before placing in `where` (`String(req.body.email)`)
- [ ] No `where: req.body` / `where: { ...req.body }` - use schema validation first

## 3. Mass Assignment

**Red Flags:**
```js
// VULNERABLE - create with arbitrary fields
User.create({ ...req.body });
user.update(req.body);

// SAFE - explicit allowlist via fields option
User.create(req.body, { fields: ["email", "name"] });
user.update(req.body, { fields: ["name", "bio"] });
```

**Checklist:**
- [ ] `User.create(req.body)` / `instance.update(req.body)` patterns either pass `fields: [...]` allowlist OR
      preceded by schema validation that strips unknown keys
- [ ] `bulkCreate` likewise with `fields:`
- [ ] Sensitive columns (`role`, `isAdmin`, `tenantId`) excluded from `fields`

## 4. Multi-Tenant Scoping

**Checklist:**
- [ ] All queries on tenant-scoped models include `tenantId` in `where`
- [ ] `findByPk(id)` audited - bypasses tenant scope unless followed by explicit ownership check
- [ ] Default scope (`Model.addScope('defaultScope', ...)`) considered for tenant-scoped models

## 5. Connection / Logging

**Checklist:**
- [ ] `logging: false` (or `console.log` redacted via formatter) in production - avoids logging bound values
- [ ] SSL enforced (`dialectOptions: { ssl: { require: true, rejectUnauthorized: true } }`); `rejectUnauthorized:
      false` flagged
- [ ] `pool: { max, idle, acquire }` bounded

## References

- Sequelize raw queries: https://sequelize.org/docs/v6/core-concepts/raw-queries/
