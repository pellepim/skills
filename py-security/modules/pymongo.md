---
name: PyMongo / Motor / MongoEngine / Beanie Security Patterns
description: NoSQL operator injection, $where, mass assignment, ObjectId validation, multi-tenant scope, aggregation pipeline review
applies_to:
  - dependency: pymongo
  - dependency: motor
  - dependency: mongoengine
  - dependency: beanie
  - dependency: umongo
version: 1
last_updated: 2026-04-30
---

# PyMongo / Motor / MongoEngine / Beanie Security Patterns

Apply when project uses the official MongoDB Python driver (`pymongo` / `motor`) or an ODM
(`mongoengine`, `beanie`, `umongo`). Sister module to `node-security/modules/mongoose.md` -
same operator-injection class, Python-specific syntax. Pydantic / ODM schemas catch type
confusion at insert time but DO NOT catch query-operator injection in `find` / `update_one`.

## 1. Operator Injection

**Red Flags:**
```python
# VULNERABLE - dict body passed directly into query
users.find_one({"email": req.json["email"], "password": req.json["password"]})
# attacker posts {"email":"a@b","password":{"$ne":""}} -> matches any password

# VULNERABLE - $where with f-string (server-side JS execution)
users.find({"$where": f"this.username == '{req.json['user']}'"})
db.users.find({"$where": req.json["filter"]})

# VULNERABLE - $accumulator / $function (server-side JS in aggregation)
collection.aggregate([{"$group": {"_id": None, "x": {"$accumulator": {...}}}}])

# VULNERABLE - mongoengine with **kwargs spread from body
User.objects(**req.json).first()                                   # operator keys leak through

# VULNERABLE - beanie find with raw dict
await User.find(req.json).to_list()

# SAFE - cast to primitive before query
email = str(req.json["email"])
user = await users.find_one({"email": email})
if not user or not bcrypt.checkpw(req.json["password"].encode(), user["password_hash"]):
    raise HTTPException(401, "invalid")

# SAFE - validate via Pydantic before constructing query
class LoginIn(BaseModel):
    email: EmailStr = Field(max_length=320)
    password: str = Field(max_length=255)
data = LoginIn.model_validate(req.json)
user = await users.find_one({"email": data.email})
```

**Attack Scenario:** login endpoint accepts JSON body and feeds it into `find_one`; attacker posts `{"email":"admin@x","password":{"$ne":null}}`; `$ne` matches the stored hash; login succeeds without knowing the password.

**Checklist:**
- [ ] All query operands from `request.json`, `request.form`, `request.args`, path params are coerced (`str(x)`, `int(x)`, `bool(x)`) OR validated through a Pydantic / Marshmallow / Beanie input model BEFORE building the query dict
- [ ] No `$where`, `$function`, `$accumulator`, `mapReduce` with user input - server-side JS in MongoDB is RCE-on-DB
- [ ] No `**req.json` / `**body.dict()` splat into `Model.objects(...)` (mongoengine) or `Model.find(...)` (beanie)
- [ ] Aggregation pipelines built from request data use explicit `$match` / `$expr` construction; no `aggregate(req.json["pipeline"])`
- [ ] Pre-pass: grep `find(`, `find_one(`, `update_one(`, `update_many(`, `delete_one(`, `count_documents(` for raw `req.` / `request.` references

## 2. Mass Assignment

**Red Flags:**
```python
# VULNERABLE - request body splatted into update
users.update_one({"_id": user_id}, {"$set": req.json})             # attacker sets is_admin, tenant_id, balance
users.update_one({"_id": user_id}, {"$set": dict(req.form)})

# VULNERABLE - mongoengine save from body
user = User(**req.json); user.save()
user.update(**req.json)

# VULNERABLE - beanie set on document from body
await user.set(req.json)
await User.find_one({"_id": uid}).update({"$set": req.json})

# SAFE - explicit allowlist via Pydantic
class ProfilePatch(BaseModel):
    name: str | None = Field(default=None, max_length=255)
    bio: str | None = Field(default=None, max_length=2000)
    model_config = {"extra": "forbid"}                             # reject unknown keys
data = ProfilePatch.model_validate(req.json)
update = {k: v for k, v in data.model_dump(exclude_unset=True).items()}
await users.update_one({"_id": user_id}, {"$set": update})
```

**Checklist:**
- [ ] No `update_one(filter, {"$set": req.json})` or `Model(**req.json)` patterns
- [ ] Pydantic input models distinct from ODM document models; input model has `model_config = {"extra": "forbid"}` (or `extra = "ignore"` if intentional drop)
- [ ] Sensitive fields (`is_admin`, `is_staff`, `tenant_id`, `role`, `email_verified`, `password_hash`, `balance`) only set by server-side logic, never copied from request
- [ ] mongoengine `meta = {"strict": True}` (default); never `strict: False` on user-facing documents
- [ ] Beanie response models exclude internal fields with `Settings.projection` or by returning a separate `ResponseModel`, not the raw document

## 3. ObjectId Validation

**Red Flags:**
```python
# VULNERABLE - bson.errors.InvalidId raised; default error handler may leak stack trace
from bson import ObjectId
user = users.find_one({"_id": ObjectId(req.path["id"])})           # crashes on non-hex; attacker probes shape

# VULNERABLE - string match without conversion against ObjectId-typed field
users.find_one({"_id": req.path["id"]})                            # returns None (string never matches ObjectId)
                                                                   # if then used in `if not user: ...`, fine; if used to
                                                                   # decide "no such user, allow create", IDOR-shaped bugs follow

# SAFE - validate first
from bson import ObjectId
from bson.errors import InvalidId
try:
    oid = ObjectId(req.path["id"])
except InvalidId:
    raise HTTPException(404)                                       # never 400 with the raw error string
user = await users.find_one({"_id": oid})
if not user: raise HTTPException(404)
```

**Checklist:**
- [ ] User-supplied IDs validated with `ObjectId.is_valid(s)` or `try ObjectId(s) except InvalidId` BEFORE query
- [ ] Validation failure maps to 404, not 400 with the parsing error (avoid disclosing query shape)
- [ ] Pydantic models declare `_id: PydanticObjectId` (beanie) or a custom validator that runs `ObjectId.is_valid`

## 4. Multi-Tenant Scoping

**Red Flags:**
```python
# VULNERABLE - find_one_by_id bypasses tenant scope
doc = await documents.find_one({"_id": ObjectId(doc_id)})          # cross-tenant IDOR

# VULNERABLE - tenant filter dropped after one branch returns
if user.is_admin:
    docs = await documents.find({}).to_list()                       # OK
else:
    docs = await documents.find({"tenant_id": user.tenant_id}).to_list()
# then later in the same handler:
target = await documents.find_one({"_id": ObjectId(doc_id)})        # forgot tenant scope here

# SAFE - helper that always includes tenant_id; cannot be called without it
async def find_doc(doc_id: str, tenant_id: str) -> dict | None:
    return await documents.find_one({"_id": ObjectId(doc_id), "tenant_id": tenant_id})
```

**Checklist:**
- [ ] Every query on tenant-scoped collections includes `tenant_id` in the filter (or is justified for global / admin paths)
- [ ] No `find_by_id(id)` / `find_one({"_id": x})` helpers that omit tenant scope - prefer `find_one({"_id": x, "tenant_id": t})`
- [ ] beanie / mongoengine query helpers / `Document.get(id)` audited - they bypass tenant filters
- [ ] Aggregation `$lookup` does not pull cross-tenant data; `let`/`pipeline` matches tenant scope
- [ ] See `multitenancy.md` for ContextVar propagation across async boundaries

## 5. Aggregation Pipelines

**Red Flags:**
```python
# VULNERABLE - user input becomes pipeline stages
collection.aggregate(req.json["pipeline"])

# VULNERABLE - $expr / $function with user data
collection.aggregate([{"$match": {"$expr": {"$function": {"body": user_code, "args": [], "lang": "js"}}}}])

# VULNERABLE - allowDiskUse=True with user-controlled grouping (disk-fill DoS)
collection.aggregate(pipeline, allowDiskUse=True)
```

**Checklist:**
- [ ] User input never IS the aggregation pipeline; only filters values inside a server-built pipeline
- [ ] No `$function` / `$accumulator` (server-side JS) with user data
- [ ] `$match` / `$expr` operands coerced to primitives, like in regular queries
- [ ] `allowDiskUse=True` set deliberately, with `$limit` early in pipeline to cap result size
- [ ] `$lookup` cross-collection joins reviewed for tenant isolation

## 6. Connection / TLS

**Checklist:**
- [ ] `MONGODB_URI` from secret manager / env; not committed
- [ ] TLS enforced (`tls=true`); never `tlsAllowInvalidCertificates=true` or `tlsInsecure=true`
- [ ] Connection options: `authSource`, `replicaSet`, `retryWrites=true`, `w=majority` set as required
- [ ] No `directConnection=true` against a replica set in prod (loses failover)
- [ ] Driver version pinned and current (CVE history on `pymongo` is short but TLS defaults changed across versions)

## 7. GridFS Uploads

**Checklist:**
- [ ] File metadata (`filename`, `metadata.*`) validated; user-controlled `filename` reflected in `Content-Disposition` is sanitized
- [ ] Size cap enforced before / during upload (`gridfs.GridIn` does NOT cap by default)
- [ ] See `file-upload.md` for archive / image-decode bombs

## 8. Change Streams / Tailable Cursors

**Checklist:**
- [ ] Change stream consumers re-check tenant scope on each event - `resumeToken` survives restarts but does not enforce authz
- [ ] No raw filter from user query into `watch(pipeline=...)`

## References

- OWASP NoSQL injection: https://owasp.org/www-community/Injection_Theory
- PyMongo docs: https://pymongo.readthedocs.io/
- Beanie: https://beanie-odm.dev/
- MongoDB `$where` / server-side JS: https://www.mongodb.com/docs/manual/reference/operator/query/where/
