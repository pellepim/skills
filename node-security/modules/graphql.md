---
name: GraphQL Security Patterns
description: Depth/complexity limits, introspection, batching, N+1 auth, persisted queries, subscriptions auth
applies_to:
  - feature: graphql
  - dependency: graphql
  - dependency: apollo-server
  - dependency: "@apollo/server"
  - dependency: "graphql-yoga"
  - dependency: mercurius
  - dependency: type-graphql
version: 1
last_updated: 2026-04-30
---

# GraphQL Security Patterns

Apply when the project exposes a GraphQL API. Most GraphQL-specific risks stem from the flexibility
of the query language: a single endpoint can return arbitrary shapes, and depth/complexity limits
must be enforced explicitly.

## 1. Introspection in Production

**Red Flags:**
```js
// VULNERABLE - introspection enabled in prod (Apollo default in dev; flip off for prod)
new ApolloServer({ schema, introspection: true });
```

**Checklist:**
- [ ] `introspection: false` in production (or auth-gated)
- [ ] Schema not committed in a repo accessible to attackers (does not eliminate exposure but reduces it)
- [ ] GraphQL Playground / GraphiQL UI disabled or auth-gated in production

## 2. Query Depth & Complexity

**Red Flags:**
```graphql
# VULNERABLE - unbounded recursion (User -> friends -> friends -> friends ...)
{ user { friends { friends { friends { friends { name } } } } } }
```

**Checklist:**
- [ ] Depth limit configured (`graphql-depth-limit`, `@graphql-tools/utils` `createComplexityRule`)
- [ ] Complexity / cost analysis with per-field weights (`graphql-cost-analysis`, `graphql-validation-complexity`)
- [ ] Hard cap on query length (kilobytes) at the HTTP layer
- [ ] Persisted-queries / APQ (allowlist of known queries, identified by hash) for production - eliminates arbitrary
      query DoS

## 3. Batching / Aliasing Abuse

**Red Flags:**
```graphql
# VULNERABLE - alias-based brute force
{ a: login(email: "x", password: "p1") { token }
  b: login(email: "x", password: "p2") { token }
  c: login(email: "x", password: "p3") { token }
  ... }                                                         # 1000 aliases per request
```

**Checklist:**
- [ ] Rate limits applied per *operation* (count of aliases / nodes), not just per HTTP request
- [ ] Mutations like `login`, `passwordReset` rate-limited by account (email/userId) at the resolver level - not just
      by IP
- [ ] Apollo `allowBatchedHttpRequests: false` (default) unless batching is needed; if needed, cap batch size

## 4. Field-Level Authorization

**Red Flags:**
```js
// VULNERABLE - auth at endpoint level only; nested field accesses cross-tenant data
const resolvers = {
  Query: {
    me: (_, __, ctx) => ctx.user,                               // OK
  },
  User: {
    posts: (parent) => Post.find({ authorId: parent.id }),      // returns posts of any user the schema allows you to navigate to
  },
};
// attacker queries: { user(id: "victim") { posts { ... } } }
```

**Checklist:**
- [ ] Authorization enforced at the resolver level for every field that reads sensitive data, not just at the entry
      query
- [ ] Use `graphql-shield` or directive-based auth (`@auth(requires: ROLE)`) consistently - do not mix-and-match
- [ ] Cross-tenant data access blocked: every resolver that loads data by ID checks `ctx.user.tenantId`
- [ ] Type-level deny for sensitive types in unauthenticated context (no `passwordHash` field in the public schema at
      all)

## 5. Mutations - Mass Assignment

**Red Flags:**
```js
// VULNERABLE - input mirrors entity, includes role
input UpdateUserInput { name: String, role: String }
# resolver
updateUser: (_, { input }) => User.update(input)                # attacker sets role
```

**Checklist:**
- [ ] Input types contain only client-settable fields (no `role`, `isAdmin`, `tenantId`)
- [ ] Output types separate from entity; sensitive fields excluded from output (`passwordHash`, `mfaSecret`)
- [ ] Resolvers do not splat `input` into ORM `data:` without an allowlist

## 6. Subscriptions

**Red Flags:**
```js
// VULNERABLE - subscription accessible without auth check on connection
new SubscriptionServer({ execute, subscribe, schema }, { server });

// VULNERABLE - per-message auth missing; user A subscribes to channel and receives user B's events
```

**Checklist:**
- [ ] WebSocket connection authenticated at handshake (`onConnect` / `context` builder verifies the connection
      params / cookie)
- [ ] Per-subscription authorization: filter events server-side based on the subscriber's identity (do not rely on
      client to filter)
- [ ] Tenant isolation in pub/sub channel names (include tenant ID in channel) so an attacker cannot subscribe to a
      channel they should not see

## 7. File Uploads via GraphQL

**Checklist:**
- [ ] If using `graphql-upload`: pin a maintained version (the original `graphql-upload` had a security advisory in
      2024 around CSRF; v17+ includes the fix or use `graphql-upload-minimal`)
- [ ] CSRF prevention: require a custom header on multipart requests (Apollo's default `csrfPrevention: true` enforces
      this for non-multipart; verify multipart handling)
- [ ] All file-upload rules from `modules/file-upload.md` apply

## 8. Errors / Stack Traces

**Red Flags:**
```js
// VULNERABLE - errors leak stack traces in production
new ApolloServer({ schema });                                   // default: includes stack in dev only, but check
```

**Checklist:**
- [ ] Apollo `formatError` strips stack traces and internal messages in production
- [ ] Custom error classes (`AuthenticationError`, `ForbiddenError`) used - clients receive generic messages
- [ ] Validation errors do not leak schema details (e.g. don't echo back the entire query that triggered it)

## 9. CSRF on POST / GET

**Checklist:**
- [ ] GraphQL endpoint accepts POST only (or GET only for queries with explicit `csrfPrevention`)
- [ ] Apollo Server v4: `csrfPrevention: true` set explicitly (default true)
- [ ] When cookie-based auth is in use: ensure preflight / Origin checks reject cross-site requests

## References

- Apollo Server security: https://www.apollographql.com/docs/apollo-server/security/
- OWASP GraphQL Cheat Sheet
