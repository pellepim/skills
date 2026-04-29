---
name: SQLAlchemy Security Patterns
description: text() with f-strings, raw connection.execute, autoflush in auth checks, bulk update bypassing validators
applies_to:
  - dependency: sqlalchemy
  - dependency: flask-sqlalchemy
  - dependency: sqlmodel
version: 1
last_updated: 2026-04-29
---

# SQLAlchemy Security Patterns

Apply when the project uses SQLAlchemy (Core or ORM), SQLModel, or Flask-SQLAlchemy.

## 1. text() and Raw SQL

**Red Flags:**
```python
# VULNERABLE - f-string into text()
session.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))

# VULNERABLE - .format()
session.execute(text("SELECT * FROM users WHERE email = '{}'".format(email)))

# VULNERABLE - concatenation
session.execute(text("SELECT * FROM users WHERE email = '" + email + "'"))

# SAFE - bound parameters
session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email},
)
```

**Checklist:**
- [ ] Grep for `text(f"`, `text(".format`, `text("` near `+` — every hit uses `:name` binds, no interpolation
- [ ] `connection.execute("...")` strings reviewed identically (Core API has the same pitfall)
- [ ] Dynamic table/column names (when truly needed) validated against an allowlist before composing into the SQL string
- [ ] `.from_statement(text(...))` follows the same rule as `text()`

## 2. ORM Filter Construction

**Red Flags:**
```python
# VULNERABLE - filter() / where() with text and interpolation
User.query.filter(text(f"email = '{email}'"))
session.scalars(select(User).where(text(f"role = '{role}'")))

# SAFE - column expressions
User.query.filter(User.email == email)
session.scalars(select(User).where(User.role == role))
```

**Checklist:**
- [ ] `.filter()` / `.where()` use column-attribute comparisons, not `text()` strings
- [ ] LIKE / ILIKE wildcards (`%`, `_`) escaped when the user controls the search term:
  ```python
  pattern = email.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
  query.filter(User.email.ilike(f"%{pattern}%", escape="\\"))
  ```
- [ ] `order_by` with user input validated against an allowlist (column injection attack)

## 3. Bulk Operations Bypassing Validators

**Red Flags:**
```python
# VULNERABLE - bulk_update_mappings does NOT trigger ORM events / validators
session.bulk_update_mappings(User, [{"id": uid, "role": new_role} for uid, new_role in payload])
# Custom @validates("role") never runs.

# VULNERABLE - core update() also bypasses ORM events
session.execute(update(User).where(User.id == uid).values(role=new_role))
```

**Checklist:**
- [ ] `bulk_insert_mappings`, `bulk_update_mappings`, `bulk_save_objects` not used on user input without re-validating fields explicitly
- [ ] Core `update()` / `delete()` statements on user-controlled values document that ORM events are skipped, and validation happens at the API layer instead
- [ ] Mass-update endpoints check authorization per row (or via WHERE clause that includes ownership), not just on the request

## 4. Autoflush During Auth Checks

**Red Flag:**
```python
# Subtle - autoflush during a permission check pushes a partially-validated object to the DB
def can_user_do(user, action):
    user.last_check_attempt = now()   # mutation
    return policy.evaluate(user, action)
    # ^ session.execute() inside policy.evaluate triggers autoflush, persisting the mutation
    #   even if the request later 403s and the response handler "rolls back" cosmetically

# SAFE - separate the read path from any write
with session.no_autoflush:
    return policy.evaluate(user, action)
```

**Checklist:**
- [ ] Permission checks do not mutate ORM objects on the path to the decision
- [ ] Read-heavy auth helpers wrapped in `session.no_autoflush` if any in-memory mutations exist
- [ ] Session lifecycle clear: one transaction per request, explicit commit/rollback, no leaked sessions across requests

## 5. Hybrid Properties / Computed Columns

**Red Flags:**
```python
# VULNERABLE - hybrid_property used in filter generates SQL from Python expression;
# user input flowing into the Python branch may interpolate unsafely if the property uses text()
class User(Base):
    @hybrid_property
    def display_name(self):
        return self.first_name + " " + self.last_name
    @display_name.expression
    def display_name(cls):
        return func.concat(cls.first_name, " ", cls.last_name)

User.query.filter(User.display_name == user_input)  # SAFE because expression uses func/columns
```

**Checklist:**
- [ ] Hybrid `@expression` implementations use column expressions and `func.*`, never `text()` with f-strings
- [ ] `column_property` / `deferred` columns reviewed for the same pattern

## 6. Connection String / Credentials

**Checklist:**
- [ ] DB URL from environment / secret manager, not committed
- [ ] Application user has minimum privileges (no DDL in production unless migrations)
- [ ] Separate connection pools / users for read replicas vs primary
- [ ] `echo=True` only in development (logs queries with values)
- [ ] TLS to the database (`sslmode=require` for Postgres) when crossing networks

## 7. Transaction Boundaries

**Checklist:**
- [ ] Money-moving / state-changing operations wrapped in explicit transactions; no implicit autocommit
- [ ] Long-running transactions avoided (lock contention, replication lag); break into smaller commits
- [ ] `SELECT ... FOR UPDATE` (`with_for_update()`) used for "check then modify" patterns to prevent race conditions
- [ ] On error, explicit `session.rollback()`; do not let the session hold an aborted transaction across requests

## References

- SQLAlchemy textual SQL: https://docs.sqlalchemy.org/en/20/core/tutorial.html#using-textual-sql
- SQLAlchemy events: https://docs.sqlalchemy.org/en/20/orm/events.html
