---
name: GraphQL Security Patterns
description: Depth/complexity caps, introspection, batching, N+1 auth, injection via variables, and subscriptions
applies_to:
  - feature: graphql
  - dependency: strawberry-graphql
  - dependency: ariadne
  - dependency: graphene
  - dependency: graphql-core
  - dependency: graphene-django
version: 1
last_updated: 2026-04-29
---

# GraphQL Security Patterns

Optional module for the `/security` skill. Apply when the project exposes a GraphQL API (Strawberry, Ariadne, Graphene,
or raw graphql-core).

## 1. Query Depth and Complexity

**Red Flags:**
```graphql
# VULNERABLE - no depth limit allows recursive queries
query {
  user {
    friends {
      friends {
        friends {
          friends { # ...100 levels deep, exponential DB load
            name
          }
        }
      }
    }
  }
}
```

**Checklist:**
- [ ] Max query depth enforced (typically 7-15 depending on schema)
- [ ] Query complexity/cost analysis enabled (weighted by field resolver cost)
- [ ] Complexity limit set per query (reject before execution, not after)
- [ ] Pagination enforced on list fields (`first`/`last` with max cap, no unbounded lists)

## 2. Introspection Exposure

**Red Flags:**
```python
# VULNERABLE - introspection enabled in production
schema = graphene.Schema(query=Query, mutation=Mutation)
# Default: introspection ON, exposes entire schema to attackers

# SAFE - disable in production
schema = graphene.Schema(query=Query, mutation=Mutation)
if not settings.DEBUG:
    # Disable introspection via middleware or validation rule
```

**Checklist:**
- [ ] Introspection disabled in production (or restricted to authenticated admin)
- [ ] Schema not exposed via error messages (field suggestions disabled)
- [ ] `__schema` and `__type` queries blocked for unauthenticated users

## 3. Batching Attacks

**Red Flags:**
```json
// VULNERABLE - no limit on batch size
[
  {"query": "mutation { login(user:\"a\", pass:\"1\") { token } }"},
  {"query": "mutation { login(user:\"a\", pass:\"2\") { token } }"},
  // ...1000 login attempts in a single HTTP request, bypassing rate limiting
]
```

**Checklist:**
- [ ] Batch query limit enforced (max 5-10 operations per request)
- [ ] Rate limiting applies per-operation, not per-HTTP-request
- [ ] Alias-based batching also limited (multiple aliased mutations in one query)
- [ ] If batching not needed, disable it entirely

## 4. Authorization Bypass (N+1 Auth)

**Red Flags:**
```python
# VULNERABLE - auth check on parent, not on resolved child
class UserType:
    @requires_auth  # Checks auth here...
    def resolve_user(self, info, id):
        return User.objects.get(id=id)

    def resolve_private_notes(self, info):
        return self.notes.all()  # ...but not here. Any authenticated user sees any user's notes.
```

**Checklist:**
- [ ] Authorization enforced at resolver level, not just root query/mutation
- [ ] Nested resolvers check the requesting user has access to the parent resource
- [ ] Mutations enforce ownership/role checks in the resolver, not just the schema directive
- [ ] Field-level auth for sensitive fields (email, phone, SSN) even on "owned" objects

## 5. Injection via Variables

**Red Flags:**
```python
# VULNERABLE - variables interpolated into raw SQL/queries
def resolve_users(self, info, filter):
    return db.execute(f"SELECT * FROM users WHERE name LIKE '%{filter}%'")

# SAFE - parameterized
def resolve_users(self, info, filter):
    return db.execute("SELECT * FROM users WHERE name LIKE %s", (f"%{filter}%",))
```

**Checklist:**
- [ ] Query variables treated as untrusted input (same injection rules as REST)
- [ ] Custom scalars validate and sanitize input
- [ ] Directives that accept string arguments are not vulnerable to injection

## 6. Denial of Service

**Checklist:**
- [ ] Query timeout enforced (kill long-running resolvers)
- [ ] Max query size in bytes (reject before parsing; prevents parser-level DoS)
- [ ] Field count limit per query
- [ ] Subscription connections limited per user/IP
- [ ] Persisted/allowlisted queries in production (if feasible; eliminates arbitrary query attacks)

## 7. Error Handling

**Red Flags:**
```python
# VULNERABLE - raw exceptions leak stack traces
@app.exception_handler(Exception)
def handle(request, exc):
    return GraphQLResponse(errors=[{"message": str(exc)}])  # May contain SQL, paths, etc.
```

**Checklist:**
- [ ] Production errors return generic messages (not stack traces, SQL errors, or file paths)
- [ ] Debug/verbose error mode disabled in production
- [ ] Resolver exceptions logged server-side with context, sanitized for client response
- [ ] Partial data responses do not leak unauthorized fields in the `errors` array

## 8. Subscription Security (if WebSocket-based)

**Checklist:**
- [ ] Authentication validated on WebSocket upgrade (not just initial HTTP)
- [ ] Authorization re-checked on each subscription event (user may lose access mid-stream)
- [ ] Subscription rate limited (max active subscriptions per user)
- [ ] Subscription payloads do not leak data from other tenants/users
