---
name: Knex Security Patterns
description: knex.raw interpolation, whereRaw, orderByRaw, table/column allowlists
applies_to:
  - dependency: knex
version: 1
last_updated: 2026-04-30
---

# Knex Security Patterns

Apply when the project uses Knex (directly or via Objection.js).

## 1. raw / whereRaw / orderByRaw

**Red Flags:**
```js
// VULNERABLE - interpolation
knex.raw(`SELECT * FROM users WHERE email = '${email}'`);
knex("users").whereRaw(`email = '${email}'`);
knex("users").orderByRaw(req.query.sort);
knex("users").select(knex.raw(`?? as alias`, req.query.col));   // ?? = identifier; OK if validated

// SAFE
knex.raw("SELECT * FROM users WHERE email = ?", [email]);
knex.raw("SELECT * FROM users WHERE email = :email", { email });
knex("users").whereRaw("email = ?", [email]);
knex("users").where({ email });                                 // builder, no raw
knex("users").orderBy(ALLOWED_COLS[req.query.sort] ?? "id", "desc");
```

**Checklist:**
- [ ] `knex.raw(...)`, `whereRaw(...)`, `orWhereRaw(...)`, `havingRaw(...)`, `orderByRaw(...)`, `groupByRaw(...)` use
      `?` / `:name` bindings - never interpolation
- [ ] `??` (identifier binding) used for column / table names; the value validated against an allowlist before passing
- [ ] LIKE patterns escape `%` and `_` if user input is the search term
- [ ] No string concatenation with SQL keywords in builder calls

## 2. Migrations & Schema

**Checklist:**
- [ ] Migrations do not interpolate user input (migration files should be static SQL)
- [ ] `knex.schema.raw(...)` used only with static strings
- [ ] Migrations reviewed for accidental relaxation of constraints (NOT NULL → NULL, length cap removed)

## 3. Connection / Pool

**Checklist:**
- [ ] SSL enforced (`connection: { ssl: { rejectUnauthorized: true } }`)
- [ ] Pool size bounded (`pool: { min, max }`)
- [ ] Credentials from secret manager / env, not committed

## References

- Knex raw queries: https://knexjs.org/guide/raw.html
