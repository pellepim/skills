---
name: security
description: Security Agent - Identify OWASP Top 10 vulnerabilities and security issues in Python projects
---

# Security Agent - Vulnerability Assessment Mode

Identify OWASP Top 10 vulnerabilities and security misconfigurations in Python web applications.

## Quick Reference

- **Reads:** Codebase (especially auth, database, templates, API routes)
- **Writes:** Findings report only
- **Can commit:** No

## OWASP Categories

| Category | Code | Focus Area |
|----------|------|------------|
| Broken Access Control | A01 | Ownership checks, IDOR, privilege escalation, CSRF |
| Cryptographic Failures | A02 | Password hashing, token generation, JWT, TLS verification, timing attacks, weak ciphers, data exposure |
| Injection | A03 | SQL, XSS, command injection, SSTI, XXE, path traversal, log injection |
| Insecure Design | A04 | Mass assignment, business-logic flaws, missing rate limits on sensitive flows |
| Security Misconfiguration | A05 | CORS, cookies, headers, debug mode, trusted-proxy boundaries |
| Vulnerable Components | A06 | Dependency scanning (`pip-audit`, `safety`, `osv-scanner`) |
| Auth Failures | A07 | Password handling, session management, MFA, webhook signature verification |
| Data Integrity | A08 | Deserialization, YAML/pickle, eval, decompression bombs |
| Logging Failures | A09 | Auth events, log injection |
| SSRF | A10 | URL fetching with user input, metadata endpoint, DNS rebinding |
| Unbounded Input | - | Missing length limits on string fields, unbounded JSON bodies |
| Resource Exhaustion | - | ReDoS, decompression bombs, unbounded recursion |
| Race / TOCTOU | - | Async shared state, idempotency, file create-then-check |
| Policy Consistency | - | Settings/UI promise X but code does not enforce X |

## Optional Modules (Dynamic Discovery)

Modules live in `modules/*.md`. Each declares triggers in YAML frontmatter:

```yaml
---
name: <module name>
description: <one-liner>
applies_to:
  - feature: <name>      # explicit feature name
  - framework: <name>    # django, fastapi, flask, drf
  - dependency: <pypi>   # detect via requirements.txt / pyproject.toml / poetry.lock
  - any                  # always-on
version: <int>
last_updated: <YYYY-MM-DD>
---
```

**Discovery procedure (run at scan start):**

1. List `modules/*.md` (skip files starting with `_`, e.g. `_template.md`, `_index.md`).
2. Parse each module's frontmatter `applies_to`.
3. For each trigger:
   - `feature:` — match against user-stated scope, or grep evidence (e.g. `saml` ↔ `samlp:`, `oauth2` ↔ `/authorize`, `webauthn` ↔ `navigator.credentials`).
   - `framework:` — match imports / settings (`from django` → django, `from fastapi` → fastapi, etc.).
   - `dependency:` — match against `requirements.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`.
   - `any` — always load.
4. Read every matched module and apply its checklists during the scan.
5. Record in the report which modules were loaded and which were skipped (with reason).

`modules/_index.md` is a human-readable summary of available modules. `modules/_template.md` is the contract for new modules.

**Adding a module:** copy `_template.md`, fill frontmatter, write Red Flags + Checklists. No edit to `SKILL.md` needed.

## Workflow

### 0. Static Analyzer Pre-Pass

Before manual review, run the cheap automated checks. They catch the obvious cases and let manual review focus on what tools cannot see (auth logic, IDOR, policy consistency, business logic).

See `tools/` for invocation details. Quick reference:

```bash
# Dependencies
pip-audit                                            # known CVEs
# Python lints
ruff check --select=S --exclude=tests,migrations .   # bandit rules via ruff
# Pattern-based
semgrep --config=p/python --config=p/owasp-top-ten --baseline-ref=origin/main .
# Secrets
gitleaks detect --log-opts="origin/main..HEAD" -v
```

Triage tool output before reporting:
- High-confidence findings (e.g. `verify=False`, `pickle.loads(request.body)`, `shell=True` with f-string) → include directly.
- Medium-confidence (e.g. SQL string-formatting flags) → verify reachability with user input first.
- Known false positives → suppress with rule ID + reason inline (`# nosec B602 -- argv list, no user input`).

Tool output is a starting point, not the report.

### 1. Orientation

Ask the user:
- **Scope:** Full assessment or specific area?
- **Focus:** All categories or specific concern?
- **Context:** First review, verification, or known concern?

### 2. Systematic Scanning

#### Injection (A03)

**SQL Injection — Red Flags:**
```python
# VULNERABLE - string formatting
query = f"SELECT * FROM users WHERE email = '{email}'"
query = "SELECT * FROM users WHERE email = '%s'" % email
query = "SELECT * FROM users WHERE email = '{}'".format(email)

# SAFE - parameterized
cursor.execute("SELECT * FROM users WHERE email = %s", (email,))  # psycopg2
cursor.execute("SELECT * FROM users WHERE email = :email", {"email": email})  # SQLAlchemy
```

**SQL Injection — Checklist:**
- [ ] Search for `f"` or `f'` near SQL keywords (SELECT, INSERT, UPDATE, DELETE)
- [ ] Search for `.format(` near SQL
- [ ] Search for `%` string formatting near SQL
- [ ] Check dynamic table/column names are validated against allowlists
- [ ] Review search/filter endpoints for proper wildcard escaping (`%`, `_`)

**XSS — Red Flags:**
```html
<!-- VULNERABLE (Jinja2) -->
{{ user_input | safe }}

<!-- SAFE - auto-escaped -->
{{ user_input }}
```

```python
# VULNERABLE (Django)
mark_safe(f"<p>{user_input}</p>")

# SAFE
from django.utils.html import escape
mark_safe(f"<p>{escape(user_input)}</p>")
```

```javascript
// VULNERABLE - innerHTML with unescaped interpolation
el.innerHTML = `<p>${data.name}</p>`;

// SAFE - escape wrapper
el.innerHTML = `<p>${escapeHtml(data.name)}</p>`;

// SAFE - textContent (no HTML parsing)
el.textContent = data.name;
```

**XSS — Checklist:**
- [ ] Search templates for `| safe` (Jinja2) or `mark_safe` (Django) without justification
- [ ] Search for `innerHTML` assignments with `${` interpolation missing escaping
- [ ] Review JavaScript that handles user data
- [ ] Check API responses that reflect user input
- [ ] Verify CSP headers are configured

**Command Injection — Red Flags:**
```python
# VULNERABLE - shell=True with interpolation
subprocess.run(f"convert {filename} out.png", shell=True)
subprocess.Popen(f"git clone {repo_url}", shell=True)
os.system(f"ping {host}")
os.popen(f"grep {pattern} file")

# VULNERABLE - shell=True with list joined back into a string
subprocess.run(" ".join(args), shell=True)

# SAFE - argv list, no shell
subprocess.run(["convert", filename, "out.png"], shell=False, check=True)
subprocess.run(["git", "clone", repo_url], check=True)

# SAFE - if shell truly needed (rare)
subprocess.run(f"convert {shlex.quote(filename)} out.png", shell=True, check=True)
```

**Command Injection — Checklist:**
- [ ] Grep for `shell=True` — every hit must use a static command or `shlex.quote` on every interpolated value
- [ ] Grep for `os.system`, `os.popen`, `commands.getoutput` — replace with `subprocess.run([...])`
- [ ] No user input flowing into `Popen(args, shell=True)` or `subprocess.call(str)`
- [ ] `git`, `convert`, `ffmpeg`, `pdftk`, `tar`, `unzip` invocations use argv list form
- [ ] PATH not user-controllable (env vars sanitized for spawned processes)

**SSTI (Server-Side Template Injection) — Red Flags:**
```python
# VULNERABLE - Jinja2 rendering user-controlled template
from jinja2 import Template
Template(user_input).render(...)
env.from_string(user_input).render(...)

# VULNERABLE - Flask render_template_string with user input
return render_template_string(f"<h1>Hello {name}</h1>")  # name = "{{config}}" leaks app config

# VULNERABLE - Django Template engine on user input
Template(user_input).render(Context({}))

# SAFE - render fixed template, pass user data as variable
return render_template("greeting.html", name=name)
return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
```

**SSTI — Checklist:**
- [ ] No user input passed as template *source* to `Template(...)`, `Environment.from_string(...)`, `render_template_string(...)`
- [ ] User input only passed as *variables* into pre-authored templates
- [ ] If user-authored templates are a feature (CMS, email templates), use `jinja2.SandboxedEnvironment` AND assume sandbox bypass exists; isolate the renderer
- [ ] Grep for `from_string`, `render_template_string`, `Template(` near request data

**XXE / Unsafe XML — Red Flags:**
```python
# VULNERABLE - stdlib XML with external entities
import xml.etree.ElementTree as ET
tree = ET.fromstring(user_xml)  # billion laughs and external entities still possible in older runtimes
import xml.sax
xml.sax.parseString(user_xml, handler)
from lxml import etree
etree.fromstring(user_xml)  # resolve_entities=True by default

# VULNERABLE - XML-RPC / SOAP with default parsers
xmlrpc.client.loads(user_payload)

# SAFE
from defusedxml import ElementTree as ET
ET.fromstring(user_xml)

from defusedxml.lxml import fromstring
fromstring(user_xml)

# SAFE - lxml with hardened parser
parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
etree.fromstring(user_xml, parser)
```

**XXE — Checklist:**
- [ ] Replace `xml.etree`, `xml.sax`, `xml.dom`, `xmlrpc`, `lxml.etree.fromstring` on untrusted input with `defusedxml` equivalents
- [ ] `lxml` parsers explicitly set `resolve_entities=False`, `no_network=True`, `huge_tree=False`
- [ ] SOAP/SAML/OOXML/SVG/RSS/Atom parsers reviewed (all are XML)
- [ ] DOCTYPE declarations rejected on untrusted input (no DTD parsing)

**Path Traversal — Red Flags:**
```python
# VULNERABLE
open(os.path.join(BASE_DIR, user_filename))  # "../../etc/passwd"
Path(BASE_DIR) / user_filename                # same problem
send_file(f"uploads/{user_path}")
os.remove(user_path)

# VULNERABLE - resolve() not boundary-checked
target = Path(BASE_DIR / user_filename).resolve()
return target.read_text()  # symlink/.. still escapes

# SAFE - resolve and verify under base
base = Path(BASE_DIR).resolve()
target = (base / user_filename).resolve()
if not target.is_relative_to(base):
    raise PermissionError("path traversal")
return target.read_text()
```

**Path Traversal — Checklist:**
- [ ] Every `open(...)`, `Path(...)`, `send_file(...)`, `os.remove`, `shutil.copy/move`, `pathlib` op on user input goes through a base-directory boundary check
- [ ] Use `Path.resolve()` + `is_relative_to(base.resolve())` (Python 3.9+) or equivalent prefix check on `realpath`
- [ ] Reject filenames containing `..`, `/`, `\`, null bytes (`\x00`), and Windows drive prefixes (`C:`)
- [ ] Prefer generated identifiers (UUID + extension) over user-supplied names
- [ ] Symlink-following ops (`open`, `os.path.realpath`) considered: attacker may write a symlink and read across it

#### Authentication (A07)

**Red Flags:**
```python
# VULNERABLE - weak hashing
hashlib.md5(password.encode()).hexdigest()
hashlib.sha256(password.encode()).hexdigest()

# SAFE
bcrypt.hashpw(password.encode(), bcrypt.gensalt())
argon2.PasswordHasher().hash(password)
```

**Checklist:**
- [ ] Password hashing uses bcrypt/argon2 with appropriate cost
- [ ] Session tokens use `secrets.token_urlsafe(32)` or similar (never sequential integers)
- [ ] Session regenerates on login (fixation prevention)
- [ ] Rate limiting on auth endpoints
- [ ] Password reset tokens are single-use and time-limited
- [ ] Unauthenticated endpoints with side effects (email sends) have rate limiting

#### Access Control (A01)

**Red Flags:**
```python
# VULNERABLE - no ownership check
def get_document(document_id: str):
    return db.get_document(document_id)  # Who owns this?

# SAFE
def get_document(user, document_id: str):
    doc = db.get_document(document_id)
    if doc.owner_id != user.id:
        raise PermissionError("Not your document")
```

```python
# VULNERABLE - policy check only at HTTP layer, not business logic
@app.route("/profile", methods=["POST"])
def update_profile():
    if not settings.allow_users_edit_profile:  # HTTP-only check
        abort(403)
    return service.update_profile(...)  # API route bypasses this

# SAFE - policy check in service/business logic layer
def update_profile(user, ...):
    if not can_user_edit_profile(user):  # Service enforces
        raise ForbiddenError(...)
```

**Checklist:**
- [ ] All endpoints verify resource ownership
- [ ] IDOR prevention (can't access others' resources by changing IDs)
- [ ] Role checks prevent privilege escalation
- [ ] Admin functions properly restricted
- [ ] Policy checks enforced in business logic layer, not just HTTP handlers
- [ ] CRUD lifecycle consistency (if create requires elevated role, update/delete should too)

#### Cryptographic Failures (A02)

**Sensitive Data Exposure — Red Flags:**
```python
# VULNERABLE
logger.debug(f"User login: {email}, password: {password}")
return {"error": str(exception)}  # May leak internals
SECRET_KEY = "hardcoded-secret-123"
```

**Sensitive Data — Checklist:**
- [ ] Passwords never logged
- [ ] API responses don't leak internal fields (stack traces, DB errors)
- [ ] Error messages don't reveal system internals
- [ ] Secrets not hardcoded in source (grep for `SECRET`, `KEY`, `TOKEN`, `PASSWORD` in `.py`/`.env.example`)
- [ ] Sensitive data not in URL parameters (appears in logs, referrer headers)

**Weak Randomness — Red Flags:**
```python
# VULNERABLE - random module is NOT cryptographically secure
import random
token = "".join(random.choices(string.ascii_letters, k=32))
otp = random.randint(100000, 999999)
session_id = str(uuid.uuid1())  # uuid1 is timestamp-based, predictable

# SAFE
import secrets
token = secrets.token_urlsafe(32)
otp = secrets.randbelow(900000) + 100000
session_id = secrets.token_hex(16)  # or uuid.uuid4() (random) — never uuid1
```

**Weak Randomness — Checklist:**
- [ ] `random.*` not used for tokens, session IDs, OTPs, password reset codes, nonces, keys
- [ ] `uuid.uuid1()` not used for security-relevant IDs (use `uuid4` or `secrets`)
- [ ] `os.urandom`, `secrets.token_*`, `secrets.randbelow` for all security-sensitive randomness

**Timing Attacks — Red Flags:**
```python
# VULNERABLE - == leaks timing
if api_key == stored_key: ...
if token == expected_token: ...
if hmac_digest == provided: ...

# SAFE
import hmac
if hmac.compare_digest(api_key, stored_key): ...
if hmac.compare_digest(token.encode(), expected.encode()): ...
```

**Timing — Checklist:**
- [ ] Secret/token/HMAC/signature comparison uses `hmac.compare_digest`, never `==`
- [ ] Constant-time comparison for password verification (handled by bcrypt/argon2 verify functions; do not roll your own)

**JWT — Red Flags:**
```python
# VULNERABLE - no algorithm restriction (alg=none accepted)
jwt.decode(token, key)
jwt.decode(token, key, verify=False)
jwt.decode(token, key, options={"verify_signature": False})

# VULNERABLE - accepts both HS256 and RS256 (algorithm confusion when key is RSA pub)
jwt.decode(token, public_key_pem, algorithms=["HS256", "RS256"])

# VULNERABLE - no aud/iss validation
jwt.decode(token, key, algorithms=["RS256"])  # missing audience/issuer

# SAFE
jwt.decode(token, key, algorithms=["RS256"], audience="my-api", issuer="https://issuer.example")
```

**JWT — Checklist:**
- [ ] `algorithms=` always passed explicitly; never trust the `alg` header
- [ ] `none` algorithm rejected (do not include in `algorithms=`)
- [ ] `HS256` and `RS256` not both accepted with the same key material (algorithm confusion)
- [ ] `aud` and `iss` claims validated
- [ ] `exp` enforced; clock skew bounded (typical 30-60s leeway, not minutes)
- [ ] `kid` header values constrained (no path traversal, no unbounded JWKS lookup)
- [ ] HMAC keys have ≥256 bits of entropy (random, not "secret")
- [ ] Public/private key pairs not committed; rotated with overlap window

**TLS Verification — Red Flags:**
```python
# VULNERABLE
requests.get(url, verify=False)
httpx.get(url, verify=False)
urllib3.disable_warnings(InsecureRequestWarning)
ssl_context = ssl._create_unverified_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

# SAFE - default verify=True; for custom CA bundle:
requests.get(url, verify="/etc/ssl/internal-ca.pem")
```

**TLS — Checklist:**
- [ ] No `verify=False` on `requests`, `httpx`, `aiohttp`, `urllib3`
- [ ] No `ssl.CERT_NONE`, no `_create_unverified_context`, no `check_hostname=False`
- [ ] No `urllib3.disable_warnings(InsecureRequestWarning)` (signal of disabled verify nearby)
- [ ] Internal services with private CA use `verify=<ca_bundle_path>`, not disabled verification
- [ ] Test fixtures with disabled verify isolated to test code (grep for `verify=False` outside `tests/`)

**Symmetric Crypto — Red Flags:**
```python
# VULNERABLE - ECB mode (patterns leak), DES, MD5/SHA1 for HMAC
Cipher(algorithms.AES(key), modes.ECB())
Cipher(algorithms.TripleDES(key), modes.CBC(iv))

# VULNERABLE - reused nonce with AES-GCM (catastrophic)
nonce = b"\x00" * 12
aesgcm.encrypt(nonce, pt, aad)  # reusing the same nonce across messages breaks confidentiality AND integrity

# SAFE - AES-GCM with fresh nonce per message
nonce = secrets.token_bytes(12)
ct = aesgcm.encrypt(nonce, pt, aad)
# store/transmit nonce alongside ct
```

**Symmetric Crypto — Checklist:**
- [ ] No ECB mode for anything except single-block primitives
- [ ] No DES / 3DES / RC4 / MD5 / SHA1 for new code
- [ ] AEAD (AES-GCM, ChaCha20-Poly1305) preferred over unauthenticated CBC/CTR
- [ ] Nonces/IVs random per-message (`secrets.token_bytes`) or strict counter; never reused with the same key
- [ ] Keys come from a KMS / secret store, not hardcoded or .env in repo
- [ ] Use `cryptography` library, not `pycrypto` (unmaintained) or hand-rolled crypto

#### Security Misconfiguration (A05)

**Red Flags:**
```python
# VULNERABLE
CORSMiddleware(allow_origins=["*"])
response.set_cookie("session", token)  # Missing security flags

# SAFE
response.set_cookie("session", token, httponly=True, secure=True, samesite="lax")
```

**Checklist:**
- [ ] Debug mode disabled in production
- [ ] CORS properly restricted (not `*`)
- [ ] Cookie security flags set (HttpOnly, Secure, SameSite)
- [ ] Security headers configured (X-Content-Type-Options, X-Frame-Options, etc.)

#### CSRF (A01)

**Checklist:**
- [ ] State-changing operations require CSRF tokens
- [ ] Tokens validated server-side
- [ ] SameSite cookie attribute set
- [ ] API endpoints use non-cookie auth or CSRF protection

#### Insecure Deserialization (A08)

**Red Flags:**
```python
# VULNERABLE
data = pickle.loads(request.body)
config = yaml.load(user_input)  # No SafeLoader
result = eval(user_expression)
exec(user_code)

# SAFE
config = yaml.safe_load(user_input)
data = json.loads(request.body)
```

**Checklist:**
- [ ] No `pickle.loads()` on untrusted data
- [ ] `yaml.load()` uses `Loader=SafeLoader`
- [ ] No `eval()` or `exec()` on user input
- [ ] JWT properly validated (signature, expiration, issuer)

#### Insufficient Logging (A09)

**Checklist:**
- [ ] Auth events logged (login success/failure, logout, password reset)
- [ ] Authorization failures logged
- [ ] Logs don't contain sensitive data (passwords, tokens, PII)
- [ ] Log injection prevented (structured logging, no raw user input in log strings)

#### Unbounded Input (Resource Exhaustion)

**Red Flags:**
```python
# VULNERABLE - no length limit (Pydantic)
class UserInput(BaseModel):
    name: str
    description: str | None = None

# SAFE
class UserInput(BaseModel):
    name: str = Field(max_length=255)
    description: str | None = Field(default=None, max_length=2000)
```

```python
# VULNERABLE - no length limit (FastAPI Form)
password: Annotated[str, Form()]

# SAFE
password: Annotated[str, Form(max_length=255)]
```

```python
# VULNERABLE - no length limit (Django Form)
class MyForm(forms.Form):
    name = forms.CharField()

# SAFE
class MyForm(forms.Form):
    name = forms.CharField(max_length=255)
```

```python
# VULNERABLE - no bounds on numeric security parameter
grace_period_days: int = Query(default=7)

# SAFE
grace_period_days: int = Query(default=7, ge=0, le=90)
```

**Checklist:**
- [ ] All string input fields have `max_length` (Pydantic, Django forms, FastAPI Form/Query params)
- [ ] Numeric parameters in security contexts have `ge`/`le` bounds (cert lifetimes, rate limits, timeouts)
- [ ] Database TEXT columns have length constraints (`CHECK` or `VARCHAR(N)`)
- [ ] URL fields limited to 2048 characters
- [ ] Fields typed as bare `dict`, `list`, or `Any` have either typed sub-models or a body-size cap
- [ ] JSON body endpoints have a request-body size ceiling (middleware or reverse proxy). Most Python frameworks do not cap body size by default.
- [ ] Pre-auth JSON endpoints (login, registration) have the tightest caps (~128 KiB)
- [ ] Standard limits: names 255, descriptions 2000, URLs 2048, enum-like 50, passwords 255, emails 320

#### Forwarded-Header Trust (A05)

**Red Flag:**
```python
# VULNERABLE - trusts arbitrary caller if app port is reachable directly
host = request.headers.get("x-forwarded-host") or request.headers.get("host")
```

`X-Forwarded-*` headers are proxy-controlled only when the app is strictly behind that proxy. If the app port is exposed (debug, internal network, misconfigured deploy), any caller can spoof these headers.

**Checklist:**
- [ ] Every `x-forwarded-host` / `x-forwarded-proto` / `x-forwarded-for` read is either (a) non-security (logging, cosmetic) OR (b) gated by a trusted-proxy allowlist
- [ ] Security-relevant derivations (tenant routing, rate-limit keys, origin checks) prefer server-side sources over header derivation
- [ ] Container/deploy config does NOT expose the app port directly; only the reverse proxy is externally reachable

#### SSRF (A10)

**Red Flags:**
```python
# VULNERABLE - any user-controlled URL fetched
requests.get(user_url)
httpx.get(request.json["webhook_url"])
urlopen(image_url)

# VULNERABLE - "validation" by string match (bypassable)
if "internal" not in url:
    requests.get(url)  # http://attacker.com#internal works; DNS rebinding works

# VULNERABLE - PDF/HTML rendering of user content fetches sub-resources
weasyprint.HTML(string=user_html).write_pdf()  # <img src="http://169.254.169.254/...">

# SAFE - parse, allowlist scheme/host, resolve to IP, block private ranges
from urllib.parse import urlparse
import ipaddress, socket
def safe_fetch(url: str) -> bytes:
    p = urlparse(url)
    if p.scheme not in ("http", "https"): raise ValueError("scheme")
    if p.hostname is None: raise ValueError("host")
    addrs = {ai[4][0] for ai in socket.getaddrinfo(p.hostname, None)}
    for a in addrs:
        ip = ipaddress.ip_address(a)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise ValueError("private address")
    # NOTE: still vulnerable to DNS rebinding between this check and the actual
    # fetch. For high-value endpoints, fetch via egress proxy that re-validates.
    return requests.get(url, timeout=5, allow_redirects=False).content
```

**Attack Scenarios:**
- Cloud metadata exfiltration: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS), `http://metadata.google.internal/` (GCP), `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure, requires `Metadata: true` header — but webhook senders that forward headers may add it).
- Internal service access: Redis (`http://internal-redis:6379/`), unauthenticated admin endpoints, internal Elasticsearch.
- DNS rebinding: attacker-controlled domain resolves to public IP at validation time and 169.254.169.254 at fetch time.
- Schemes beyond http: `file://`, `gopher://` (used to forge raw TCP), `dict://`, `ftp://`.

**Checklist:**
- [ ] Every `requests`, `httpx`, `aiohttp`, `urllib`, `urlopen` call on user-influenced URLs is wrapped in an SSRF guard
- [ ] Scheme allowlist: `http`, `https` only (no `file`, `gopher`, `dict`, `ftp`)
- [ ] Resolve hostname to IP and block private (RFC1918), loopback, link-local (`169.254/16`, including IPv6 `fe80::/10` and `fd00::/8`), multicast, reserved
- [ ] IP literal hosts (`http://10.0.0.1/`, decimal-encoded `http://2130706433/`) blocked
- [ ] `allow_redirects=False` or redirect target re-validated (attacker can redirect to internal target)
- [ ] Timeouts set on all outbound HTTP (5-10s typical)
- [ ] For high-value flows (webhooks, image proxy, PDF rendering): outbound traffic via dedicated egress proxy with allowlist + IP re-validation per connection (defeats DNS rebinding)
- [ ] Header allowlist on outbound requests (do NOT forward client `Authorization`, `Cookie`, `Metadata`, `X-aws-ec2-metadata-token`)
- [ ] Cloud metadata endpoints explicitly blocked even if private-IP check exists (defense in depth)
- [ ] PDF/HTML/SVG/Markdown renderers that follow `<img>`, `<link>`, `<iframe>` either disable network fetch or route through SSRF guard

#### Webhook Signature Verification

**Red Flags:**
```python
# VULNERABLE - no signature verification
@app.post("/webhooks/stripe")
def stripe_hook(payload: dict):
    if payload["type"] == "invoice.paid":
        mark_paid(payload["data"])  # attacker can POST arbitrary events

# VULNERABLE - == comparison leaks timing
expected = hmac.new(secret, body, sha256).hexdigest()
if expected == request.headers["X-Signature"]:
    process(body)

# VULNERABLE - no replay window
# attacker captures one valid webhook and replays it forever

# SAFE
import hmac, hashlib, time
def verify(body: bytes, sig_header: str, ts_header: str, secret: bytes, tolerance: int = 300):
    ts = int(ts_header)
    if abs(time.time() - ts) > tolerance:
        raise ValueError("timestamp outside tolerance")
    expected = hmac.new(secret, f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig_header):
        raise ValueError("bad signature")
```

**Checklist:**
- [ ] Every inbound webhook (Stripe, GitHub, Slack, Twilio, SendGrid, custom) verifies signature before any side effect
- [ ] HMAC compared with `hmac.compare_digest`, never `==`
- [ ] Signature input includes a timestamp; verifier enforces a tolerance window (typical 5 min)
- [ ] Replay protection: timestamp window OR nonce tracking with TTL
- [ ] Raw request body used for HMAC (not the parsed-then-reserialized JSON; reserialization changes bytes)
- [ ] Webhook secret stored in secret manager, rotatable, not committed
- [ ] Failed verifications logged with caller IP for abuse monitoring

#### Mass Assignment (A04)

**Red Flags:**
```python
# VULNERABLE - request body splatted into ORM (attacker sets is_admin, tenant_id, balance)
user = User(**request.json)
db.session.add(user)

# VULNERABLE - update from arbitrary dict
for k, v in request.json.items():
    setattr(user, k, v)

# VULNERABLE - Django ModelForm with no fields restriction
class UserForm(ModelForm):
    class Meta:
        model = User
        fields = "__all__"  # exposes is_staff, is_superuser, etc.

# VULNERABLE - Pydantic model_validate -> ORM kwargs
data = UserCreate.model_validate(request.json)
User.objects.create(**data.model_dump())  # only safe if UserCreate is a tight allowlist

# SAFE - explicit allowlist
ALLOWED = {"name", "bio", "avatar_url"}
for k in ALLOWED & request.json.keys():
    setattr(user, k, request.json[k])
```

**Checklist:**
- [ ] No `Model(**request.json)`, `Model(**request.form)`, `Model(**body.dict())` patterns
- [ ] DRF serializers list `fields = [...]` explicitly, never `__all__` for write paths
- [ ] Django `ModelForm.Meta.fields` lists permitted fields explicitly
- [ ] Pydantic input models distinct from ORM models; input model contains only client-settable fields
- [ ] Sensitive fields (`is_admin`, `is_staff`, `tenant_id`, `user_id`, `role`, `balance`, `email_verified`) only set by server-side logic, never copied from request
- [ ] Update endpoints use partial-update allowlists, not full-object replacement from request body

#### ReDoS (Regex Denial of Service)

**Red Flags:**
```python
# VULNERABLE - catastrophic backtracking on user input
re.match(r"^(a+)+$", user_input)
re.match(r"^(\w+\s?)*$", user_input)
re.match(r"^([a-zA-Z0-9]+)*@", user_input)  # nested quantifiers

# VULNERABLE - user-controlled regex pattern
re.match(request.args["pattern"], target)  # attacker crafts pathological regex
```

**Checklist:**
- [ ] No user input as regex *pattern* (only as input to a static pattern)
- [ ] Nested quantifiers (`(a+)+`, `(a*)*`, `(.+)*`) audited; refactor to non-backtracking forms
- [ ] Long input + complex regex combinations have a length cap on input before matching
- [ ] For untrusted regex evaluation, use `re2` (Google RE2 bindings) — linear time, no backtracking
- [ ] Validators (email, URL) use vetted libraries, not hand-rolled regex

#### Decompression Bombs (A08)

**Red Flags:**
```python
# VULNERABLE - reads entire decompressed payload into memory
import gzip, zipfile, tarfile
data = gzip.decompress(request.body)              # 10 KB compressed -> 10 GB
zipfile.ZipFile(uploaded).extractall("/tmp/x")    # zip slip + bomb
tarfile.open(uploaded).extractall("/tmp/x")       # tar slip + bomb + symlink escape

# VULNERABLE - HTTP client auto-decompresses without size cap
requests.get(url).text  # Content-Encoding: gzip with 1000:1 ratio

# SAFE - cap decompressed size + check ratio + safe extract
def safe_gunzip(data: bytes, max_bytes: int = 50_000_000) -> bytes:
    out = bytearray()
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
        while chunk := f.read(64 * 1024):
            out.extend(chunk)
            if len(out) > max_bytes:
                raise ValueError("decompression bomb")
    return bytes(out)

def safe_extract_zip(zf: zipfile.ZipFile, dest: Path, max_total: int):
    dest = dest.resolve()
    total = 0
    for member in zf.infolist():
        # zip slip
        target = (dest / member.filename).resolve()
        if not target.is_relative_to(dest):
            raise ValueError("zip slip")
        # bomb
        total += member.file_size
        if total > max_total or member.file_size > max_total:
            raise ValueError("zip bomb")
        zf.extract(member, dest)
```

**Checklist:**
- [ ] Decompression of user-supplied data is size-capped (streaming with running total)
- [ ] Compression-ratio sanity check on inbound gzip/deflate (reject ratios > ~100:1 for unknown content)
- [ ] `ZipFile.extractall` and `tarfile.extractall` never used directly on untrusted archives — manual loop with path-boundary check (zip slip / tar slip)
- [ ] `tarfile` symlink/hardlink members rejected or resolved (CVE-2007-4559 family)
- [ ] Pillow images: cap `Image.MAX_IMAGE_PIXELS`; call `verify()` before `load()`; check dimensions before decode
- [ ] HTTP clients fetching untrusted URLs cap response size (stream + abort over limit)

#### Race Conditions / TOCTOU

**Red Flags:**
```python
# VULNERABLE - check-then-use on filesystem (TOCTOU)
if not os.path.exists(path):
    open(path, "w").write(data)  # attacker creates symlink between check and open

# VULNERABLE - duplicate side effects (no idempotency)
@app.post("/charge")
def charge(req):
    db.charge_card(req.user_id, req.amount)  # double-click = double charge

# VULNERABLE - shared mutable state in async handler
counter = {"n": 0}
async def handler():
    counter["n"] += 1  # await between read and write = lost updates

# SAFE - atomic create
fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
os.write(fd, data); os.close(fd)

# SAFE - idempotency key
@app.post("/charge")
def charge(req, idempotency_key: str = Header(...)):
    if seen(idempotency_key): return prior_result(idempotency_key)
    result = db.charge_card(req.user_id, req.amount)
    record(idempotency_key, result, ttl=86400)
    return result
```

**Checklist:**
- [ ] No filesystem `os.path.exists` / `stat` followed by `open` on a path that crosses a trust boundary; use `O_CREAT | O_EXCL` or atomic `rename`
- [ ] Money-moving / account-mutating endpoints accept and dedupe on an `Idempotency-Key`
- [ ] Async handlers do not share mutable Python state across `await` points without a lock (`asyncio.Lock`)
- [ ] DB-level uniqueness or `SELECT ... FOR UPDATE` for "check uniqueness then insert" patterns (avoid app-layer race)
- [ ] Outbound HTTP/DB calls have explicit timeouts (no `await` without timeout in critical paths)
- [ ] Auth flows: token consumption (`UPDATE ... WHERE token=X AND used=false RETURNING ...`) atomic, not select-then-update

#### Redirect Validation

**Red Flag:**
```python
# VULNERABLE
return redirect(request.args.get("next", "/dashboard"))

# SAFE
target = request.args.get("next", "/dashboard")
if not target.startswith("/") or target.startswith("//") or "://" in target:
    target = "/dashboard"
return redirect(target)
```

**Checklist:**
- [ ] User-controlled redirect targets (next params, return URLs, RelayState) are validated
- [ ] Targets must be relative paths (start with `/`, not `//`, no `://`)

#### Policy Consistency (Cross-cutting)

When the codebase exposes a setting or UI string that promises a security property (required MFA, session timeout, password strength floor), trace the enforcement point and confirm it delivers the promise.

**Red Flag:**
```python
# UI says "require strong MFA" but code only checks credential exists
if policy == "strong_mfa":
    return user.has_any_mfa_credential  # Does not verify strength/type
```

**Checklist:**
- [ ] For each security policy setting, identify enforcement point(s) and confirm the check matches the promise
- [ ] Password strength thresholds applied on all paths (change, set, onboarding), not just login
- [ ] Session timeout flags honored on every session creation/regeneration path
- [ ] "Require strong MFA" gates check the actual credential type/strength, not just existence

### 3. Evidence Collection

For each vulnerability:
- Exact file and line number
- Attack scenario (how would this be exploited?)
- Exploitability (easy, moderate, difficult)
- Impact (worst case)
- Specific remediation

### 4. Report Findings

Report all findings to the user. Do not modify any code.

## Severity Guide

General floor:
- **Critical:** RCE, full database access, authentication bypass
- **High:** Data breach potential, privilege escalation, IDOR
- **Medium:** XSS, CSRF on sensitive actions, information disclosure
- **Low:** Missing headers, minor misconfigurations, theoretical risks

### Per-category severity floor

When the rubric below disagrees with intuition, use the higher severity. Authentication and authorization findings start at **High**.

| Finding | Floor | Promotes to |
|---------|-------|-------------|
| `eval` / `exec` / `pickle.loads` on untrusted input | Critical | — |
| Command injection (`shell=True` with user input) | Critical | — |
| SSTI on a request-reachable path | Critical | — |
| SQL injection on authenticated endpoint | High | Critical if pre-auth or admin role |
| SSRF reaching cloud metadata or internal services | High | Critical if exfil already possible |
| Path traversal write | High | Critical if writes to executable / cron path |
| Path traversal read | Medium | High if reads secrets / tokens |
| Auth bypass (missing `permission_classes`, missing `Depends`) | High | Critical if admin-equivalent |
| IDOR on owned resource | High | Critical if cross-tenant |
| JWT `alg=none` or algorithm confusion accepted | Critical | — |
| TLS verification disabled (`verify=False`) on prod path | High | Critical if used for auth tokens |
| Webhook signature verification missing | High | — |
| Hardcoded production secret in repo | Critical | — |
| Hardcoded test secret confused for prod | Medium | — |
| `mark_safe` / `\| safe` / `innerHTML` with user input | Medium | High if reflects to other users |
| CSRF missing on state-changing endpoint | Medium | High for money/account-mutating |
| Mass assignment on a model with privilege fields | High | Critical if `is_admin`/`is_staff` settable |
| Decompression bomb / ZIP slip on untrusted archives | High | — |
| ReDoS reachable from user input | Medium | High if pre-auth |
| Weak randomness for tokens / OTPs | High | — |
| Timing attack on token comparison (`==`) | Medium | High if pre-auth & remotely measurable |
| Missing rate limit on auth / email-trigger endpoint | Medium | High if free-tier abuse / cost amplification |
| CORS `allow_origins=["*"]` with `allow_credentials=True` | High | — |
| Forwarded-header trust without proxy allowlist | Medium | High if used for tenant routing or origin check |
| Missing security headers (HSTS, CSP, X-Frame-Options) | Low | Medium if app handles credentials and lacks all of them |
| Debug mode enabled in production | Critical | — |
| Open redirect | Low | Medium if used in OAuth/SSO flow |
| Logging of passwords / tokens | High | — |
| Missing length cap on input field | Low | Medium for pre-auth, Critical for body without overall cap |
| Insecure deserialization (`yaml.load`, `pickle`) | Critical | — |
| XXE on untrusted XML | High | Critical if file:// readable / SSRF possible |

## Delegating to Subagents

When scope is large, delegating file clusters to `Explore` subagents is fine, but the bar for a "clean" report back is evidence, not assertion. Reject reports that say "cluster X: clean" or "checked, OK" without specifics.

Require each cluster report to include:
- For every claim of the form "Y is not vulnerable to Z", quote the `file:line` that proves it (a parameterized query, an escape call, a role check dependency, etc.).
- If the subagent found the absence of something (e.g., "no `| safe` without justification"), require the exact `grep` command it ran and a count.

If a subagent returns only narrative summaries, re-delegate with an explicit "quote the lines" instruction or do the cluster yourself.

## Finding Format

```markdown
## [Vulnerability Type]: [Brief Description]

**Found in:** [File:line]
**Severity:** Critical/High/Medium/Low
**OWASP Category:** [e.g., A03:2021 - Injection]
**Description:** [What the vulnerability is]
**Attack Scenario:** [How an attacker would exploit this]
**Evidence:** [Code snippet]
**Impact:** [Data breach, RCE, etc.]
**Remediation:** [Specific code changes]

Example fix:
```python
# Current (vulnerable):
query = f"SELECT * FROM users WHERE email = '{email}'"

# Fixed (parameterized):
query = "SELECT * FROM users WHERE email = %s"
cursor.execute(query, (email,))
```

---
```

## Negative Findings (Evidence Required)

A clean review is more credible when the absence of issues is *demonstrated*, not asserted. Every report includes a "checked but clean" section. The bar is the same one applied to subagent reports: cite `file:line` evidence.

```markdown
## Categories Checked

### Triggered (see Findings above)
- A03 Injection — SQL injection in `app/api/users.py:42`
- A02 Cryptographic Failures — `verify=False` in `app/integrations/legacy.py:18`

### Clean (with evidence)
- A01 Broken Access Control — ownership check at `app/views/document.py:31` (`if doc.owner_id != user.id: raise PermissionError`); IDOR-prone routes verified
- A03 Command Injection — no `shell=True` or `os.system` in changed files (`grep -rn "shell=True\|os\.system" app/` returned 0)
- A03 SSTI — no `render_template_string` or `Template(` with user input (grep clean)
- A10 SSRF — outbound HTTP calls in `app/integrations/webhooks.py:55` go through `safe_fetch()` (allowlist + private-IP block)
- A07 JWT — `algorithms=["RS256"]` pinned at `app/auth/jwt.py:14`; `aud` and `iss` validated

### Skipped (with reason)
- A06 Vulnerable Components — `pip-audit` clean as of pre-pass; full dependency review out of scope for this PR

## Modules

### Loaded
- `fastapi.md` (matched framework:fastapi)
- `sqlalchemy.md` (matched dependency:sqlalchemy)
- `secrets.md` (always-on)

### Skipped
- `saml.md` — no SAML usage detected
- `webauthn.md` — no WebAuthn usage detected
```

Reports without this section are incomplete. "Looks fine" / "checked, OK" is not acceptable. If a category cannot be evidenced (no relevant code in scope), say so explicitly under Skipped with the reason.

## Module Versioning Rule

Every module declares `version: <int>` and `last_updated: YYYY-MM-DD` in frontmatter.

- **Bump `version`** when a checklist item is added, removed, or its meaning changes. Cosmetic edits (typo fixes, link updates) do not bump.
- **Update `last_updated`** on every merge that touches the module.
- A module with `last_updated` older than 12 months should be revisited as part of any review that loads it.

## What You Cannot Do

- No code fixes (report findings only)
- No penetration testing (code review only)
- No assumptions (verify against actual usage)

## Headless Mode

When invoked programmatically (via Agent tool), skip all interactive workflows:
- Do not ask about scope, focus, or context

### Mode A — Explicit file list

If the prompt includes a list of files:
1. Read each changed file
2. Run module discovery (list `modules/*.md`, parse frontmatter, match `applies_to` against changed files / dependency manifests, load matches)
3. Run the static-analyzer pre-pass scoped to the changed files (`semgrep --baseline-ref=origin/main` for diff-only, `ruff check --select=S` on the changed files)
4. Scan for all OWASP categories relevant to the changes
5. Report findings only

### Mode B — Diff-only (no file list)

If the prompt does not specify files:
1. Run `git diff --name-only origin/main...HEAD` to enumerate changed files
2. Skip files matching `tests/**`, `**/test_*.py`, `migrations/**`, `**/*.md` unless they are security-relevant configs (e.g. `.env.example`, `docker-compose.yml`, `Dockerfile`, `nginx.conf`)
3. Continue from step 2 of Mode A

If `git diff` returns nothing, fall back to listing files modified in the last commit (`git diff --name-only HEAD~1 HEAD`). If still empty, abort with "no changes to review."

### Reporting

Report back (for each finding):
- File and line number
- OWASP category and severity (Critical / High / Medium / Low)
- Attack scenario (how it could be exploited)
- Suggested remediation

Also report **negatives with evidence**:
- Categories checked
- Categories triggered
- Categories clean (with `file:line` citations of the safe pattern, not just "looks fine")
- Modules loaded vs skipped (with reason for skip)

If no issues found, say so explicitly. Do not edit any files.

---

## Start Here

Ask about scope, focus, and context, then proceed with systematic scanning.
