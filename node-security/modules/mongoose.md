---
name: Mongoose / MongoDB Security Patterns
description: NoSQL operator injection, $where, mass assignment via findOneAndUpdate, sanitize-mongo, populate leakage
applies_to:
  - dependency: mongoose
  - dependency: mongodb
version: 1
last_updated: 2026-04-30
---

# Mongoose / MongoDB Security Patterns

Apply when the project uses Mongoose or the native `mongodb` driver. Mongoose schemas catch most
type confusion at insert time but DO NOT catch query-operator injection in `find` / `update`.

## 1. Operator Injection

**Red Flags:**
```js
// VULNERABLE - body object passed directly into query
User.findOne({ email: req.body.email, password: req.body.password });
// attacker posts {"email":"a@b","password":{"$ne":""}} -> matches any password

// VULNERABLE - $where with user input (executes JS server-side)
User.find({ $where: `this.username == '${req.body.user}'` });
db.collection("users").find({ $where: req.body.filter });

// VULNERABLE - $accumulator / $function (server-side JS)
collection.aggregate([{ $match: { ... } }, { $group: { _id: null, x: { $accumulator: { ... } } } }]);

// SAFE - cast to primitive before query
User.findOne({ email: String(req.body.email) });
const user = await User.findOne({ email: String(req.body.email) });
if (!user || !await bcrypt.compare(req.body.password, user.passwordHash)) throw new Error("invalid");
```

**Checklist:**
- [ ] All query inputs from request body / query / params coerced to primitives (`String(x)`, `Number(x)`,
      `Boolean(x)`) OR validated by schema before use as query operands
- [ ] No `$where`, `$function`, `$accumulator`, `mapReduce` with user input
- [ ] `express-mongo-sanitize` (or `mongo-sanitize`) middleware strips `$`-prefixed keys from `req.body`/`req.query`/
      `req.params` - mounted before route handlers
- [ ] Aggregation pipelines built from user input use `$match` / `$expr` with explicit operator construction; no
      `aggregate(req.body)`

## 2. Mass Assignment

**Red Flags:**
```js
// VULNERABLE - findOneAndUpdate ignores schema validation by default
await User.findOneAndUpdate({ _id: req.user.id }, req.body);
await User.findByIdAndUpdate(req.user.id, req.body);

// VULNERABLE - new Model with body splatted
const u = new User({ ...req.body });
await u.save();

// SAFE
const Patch = z.object({ name: z.string().max(255), bio: z.string().max(2000).optional() });
const data = Patch.parse(req.body);
await User.findOneAndUpdate({ _id: req.user.id }, data, { runValidators: true });
```

**Checklist:**
- [ ] No `findOneAndUpdate(filter, req.body)`, `updateOne(filter, { $set: req.body })`, `new Model(req.body)` patterns
- [ ] When using `findOneAndUpdate` / `updateOne`, pass `{ runValidators: true }` (Mongoose by default does NOT run
      schema validators on update)
- [ ] Schema does not declare sensitive fields as user-settable (`role`, `isAdmin`, `tenantId`, `passwordHash` should
      have `select: false` and be set only by server logic)
- [ ] `strict: 'throw'` (or default `strict: true`) - never `strict: false` on user-facing models
- [ ] `findByIdAndUpdate` audited - same risks as `findOneAndUpdate`

## 3. Multi-Tenant Scoping

**Checklist:**
- [ ] All queries on tenant-scoped collections include `tenantId` in the filter
- [ ] `findById(id)` audited - bypasses tenant scope; prefer `findOne({ _id: id, tenantId })`
- [ ] Mongoose plugins or query helpers that auto-inject `tenantId` reviewed; failure mode is open (no scope) or closed
      (error)?

## 4. populate / Field Leakage

**Red Flags:**
```js
// VULNERABLE - populate fetches all fields including passwordHash
await Post.findById(id).populate("author");

// SAFE
await Post.findById(id).populate("author", "name avatarUrl");
// or, on the User schema, mark sensitive fields select: false:
// passwordHash: { type: String, select: false }
```

**Checklist:**
- [ ] `populate` calls specify a field projection or rely on `select: false` on sensitive fields in the referenced
      schema
- [ ] No `populate({ path: ..., select: req.query.fields })` - allowlist user-controlled projections

## 5. ObjectId Validation

**Red Flags:**
```js
// VULNERABLE - cast errors crash unhandled, also leak query shape via error message
await User.findById(req.params.id);                             // CastError if not ObjectId; depends on error handler

// SAFE
if (!mongoose.isValidObjectId(req.params.id)) return res.sendStatus(404);
const u = await User.findById(req.params.id);
```

**Checklist:**
- [ ] User-supplied IDs validated with `mongoose.isValidObjectId(...)` (or zod custom refinement) before query
- [ ] Cast errors not surfaced to the client with internal messages; map to 404

## 6. Connection

**Checklist:**
- [ ] `MONGODB_URI` from secret manager / env; not committed
- [ ] TLS enforced (`tls=true`, `tlsAllowInvalidCertificates=false`); never `tlsAllowInvalidCertificates=true`
- [ ] Connection options: `authSource`, `replicaSet` set as needed; `retryWrites` enabled

## 7. Aggregation Pipelines

**Checklist:**
- [ ] `$lookup` does not pull cross-tenant data; check `let` / `pipeline` matches tenant scope
- [ ] User input in aggregation stages (`$match`, `$expr`) coerced to primitives or validated; no raw `$where`
- [ ] `allowDiskUse: true` set only with awareness of disk-fill DoS risk (cap result size or use `$limit` early)

## 8. GridFS Uploads

**Checklist:**
- [ ] File metadata (`filename`, `metadata.*`) validated; user-controlled `filename` is path-like and could be reflected
      back in `Content-Disposition` - sanitize
- [ ] Size cap enforced before/during upload
- [ ] See `modules/file-upload.md`

## References

- OWASP NoSQL injection: https://owasp.org/www-community/Injection_Theory
- Mongoose `findOneAndUpdate`: https://mongoosejs.com/docs/tutorials/findoneandupdate.html
