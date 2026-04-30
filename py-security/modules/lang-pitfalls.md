---
name: Python Language-Specific Pitfalls
description: Pickle/eval, GIL false-confidence, sync/async mixing, contextvars across await, monkey-patching, format-string attr leak, decimal-vs-float, dict ordering, signal handlers
applies_to:
  - any
version: 1
last_updated: 2026-04-30
---

# Python Language-Specific Pitfalls

Always-on. Catches Python-specific footguns that do not fit a single OWASP category. Sister
module to `node-security/modules/lang-pitfalls.md`. Pairs with SKILL.md sections on injection,
deserialization, and races (no duplication: this module owns the language-shape risks; SKILL.md
owns the OWASP-category risks).

## 1. Pickle / `__reduce__` Code Execution

**Red Flags:**
```python
# VULNERABLE - any pickle deserialization of attacker-influenced bytes is RCE
import pickle
data = pickle.loads(request.body)
data = pickle.load(open(uploaded_path, "rb"))
data = dill.loads(blob)                                            # dill, cloudpickle, jsonpickle: same risk

# VULNERABLE - pickle implicit via libraries
import joblib; model = joblib.load(uploaded_path)                  # pickle under the hood
import torch; sd = torch.load(uploaded_path)                       # pickle by default; use weights_only=True (PyTorch 2.0+)
import pandas as pd; df = pd.read_pickle(uploaded_path)
import numpy as np; arr = np.load(path, allow_pickle=True)         # allow_pickle=True is the footgun
import shelve; db = shelve.open(user_path)                         # backed by pickle

# VULNERABLE - cache / message-queue serializer set to pickle
CELERY_TASK_SERIALIZER = "pickle"; CELERY_ACCEPT_CONTENT = ["pickle"]
cache.set(key, complex_object)                                     # default pickle in many django-cache backends

# SAFE
data = json.loads(request.body)
arr = np.load(path, allow_pickle=False)
sd = torch.load(uploaded_path, weights_only=True)                  # tensors only, no arbitrary code
# Celery: serializer = "json"; accept_content = ["json"]
```

**Attack Scenario:** `__reduce__` on any class in the pickle stream returns `(os.system, ("id",))`; loader executes `os.system("id")` before any application code runs.

**Checklist:**
- [ ] No `pickle.load`/`pickle.loads`/`dill.load`/`cloudpickle.load`/`jsonpickle.decode` on data crossing a trust boundary
- [ ] `joblib.load`, `torch.load`, `pd.read_pickle`, `shelve` audited for trust-boundary inputs; PyTorch use `weights_only=True`
- [ ] `numpy.load(allow_pickle=True)` flagged unless input source is fully trusted
- [ ] Celery / RQ / dramatiq: serializer is `json` or `msgpack`, never `pickle`; `accept_content` limited to safe types (see `task-queues.md`)
- [ ] Django `CACHES` backend: if pickle-based (default for `django-redis`, `locmem`), keys/values from cross-tenant or shared infra cannot be attacker-influenced
- [ ] Redis values written by other services not blindly `pickle.loads`-ed on read

## 2. eval / exec / compile on User Input

**Red Flags:**
```python
# VULNERABLE
eval(user_expression)
exec(user_code)
compile(user_src, "<string>", "exec")
ast.literal_eval(user_input)                                       # SAFER but still has DoS via deeply nested literals

# VULNERABLE - "calculator" / formula engines
result = eval(formula, {"__builtins__": {}})                       # "__builtins__: {}" is NOT a sandbox
                                                                   # ().__class__.__bases__[0].__subclasses__() escapes

# VULNERABLE - SQLAlchemy / pandas query string
df.query(user_expr)                                                # backed by eval; engine="numexpr" only partial mitigation
df.eval(user_expr)
```

**Attack Scenario:** sandboxed `eval` defeated via `().__class__.__mro__[1].__subclasses__()` walk to reach `subprocess.Popen` or `os.system`; full RCE.

**Checklist:**
- [ ] No `eval` / `exec` / `compile` on request-influenced strings, ever - empty `__builtins__` is not a sandbox
- [ ] `ast.literal_eval` only on size-bounded, depth-bounded input (cap input length and parsed AST depth)
- [ ] `pandas.DataFrame.query` / `.eval` audited - prefer typed filter builders, not user-supplied expressions
- [ ] User-supplied "formulas" / "rules" use a real expression language (asteval restricted, simpleeval) with tight allowlists, or run in a separate process with seccomp/nsjail
- [ ] No `exec(open(user_path).read())` or `runpy.run_path(user_path)` - executing user-uploaded `.py` is RCE

## 3. GIL False-Confidence on Shared State

**Red Flags:**
```python
# VULNERABLE - "GIL makes this atomic" - it does NOT for read-modify-write
counter = {"n": 0}
def handler():
    counter["n"] += 1                                              # LOAD + ADD + STORE; thread switch between LOAD and STORE
                                                                   # under load, lost updates

# VULNERABLE - free-threaded / no-GIL build (PEP 703, Python 3.13+) removes even the
# coarse single-bytecode atomicity many people assume

# VULNERABLE - check-then-act on shared dict
if key not in cache: cache[key] = compute()                        # two threads both compute

# SAFE
import threading
lock = threading.Lock()
with lock: counter["n"] += 1

# SAFE - atomic ops via concurrent primitives or single dict.setdefault
cache.setdefault(key, compute())                                   # still computes twice but only one wins
```

**Checklist:**
- [ ] No assumption that "Python is single-threaded so this is atomic" - read-modify-write on dicts/lists across threads needs a lock
- [ ] Code targeting Python 3.13+ free-threaded build (`python3.13t`) does NOT rely on GIL atomicity at all
- [ ] Caches / counters / "have we seen this nonce" patterns use `threading.Lock`, `multiprocessing.Lock`, or a real cache (Redis with `INCR`/`SETNX`)
- [ ] Idempotency / nonce stores backed by DB with unique constraint, not in-process dict

## 4. Sync DB Driver in Async Handler

**Red Flags:**
```python
# VULNERABLE - sync psycopg2/redis/requests in async handler blocks the event loop;
# under load, all requests stall until this one returns
@app.get("/x")
async def x():
    rows = psycopg2_conn.execute("SELECT ...").fetchall()          # blocks loop
    r = requests.get("https://api.example/...")                    # blocks loop
    return rows

# VULNERABLE - async function that never awaits ("accidentally sync")
async def get_user(uid):
    return User.objects.get(id=uid)                                # Django ORM is sync; runs blocking on loop thread

# SAFE - native async driver
import asyncpg, httpx
@app.get("/x")
async def x():
    rows = await pool.fetch("SELECT ...")
    r = await httpx.AsyncClient().get(...)
    return rows

# SAFE - bridge to threadpool when async driver unavailable
import anyio
result = await anyio.to_thread.run_sync(blocking_call, arg)
```

**Attack Scenario:** attacker triggers a slow sync call (DB lock, slow downstream); event loop stalls; entire async server unresponsive (DoS amplification).

**Checklist:**
- [ ] In FastAPI / Starlette / aiohttp / Sanic handlers: no `requests`, `urllib.request`, sync `psycopg2`, sync `redis-py` (use `redis.asyncio`), sync `boto3` (use `aioboto3`)
- [ ] Django ORM in async views wrapped in `sync_to_async(...)` (Django 4.1+) or routed through `asgiref.sync.async_to_sync` correctly; no bare ORM calls in `async def`
- [ ] CPU-bound work in async handlers offloaded to `anyio.to_thread.run_sync` / `asyncio.to_thread` / process pool
- [ ] Tests assert event-loop responsiveness under a simulated slow downstream (timeouts on every outbound call)

## 5. ContextVars Lost / Mixed Across `await`

**Red Flags:**
```python
# VULNERABLE - tenant context set in middleware, used in DB layer
from contextvars import ContextVar
current_tenant: ContextVar[str] = ContextVar("current_tenant")

@app.middleware("http")
async def tenant_mw(request, call_next):
    current_tenant.set(request.headers["X-Tenant"])                # NOT propagated correctly if a background task copied
                                                                   # the context BEFORE this set() ran
    return await call_next(request)

# VULNERABLE - contextvars NOT propagated by raw threadpools
import threading
threading.Thread(target=worker).start()                            # current_tenant unset in worker

# VULNERABLE - asyncio.create_task captures context AT TASK-CREATE time;
# subsequent ContextVar.set() in the spawning task does not reach the child
ctx_var.set("A")
t = asyncio.create_task(child())                                   # child sees "A"
ctx_var.set("B")
await t                                                            # child still sees "A" (sometimes desired, often not)

# SAFE - propagate explicitly when bridging to threads
import contextvars
ctx = contextvars.copy_context()
threading.Thread(target=lambda: ctx.run(worker)).start()
```

**Attack Scenario:** tenant ContextVar lost in a background task; that task issues a query without the tenant filter; cross-tenant data leak.

**Checklist:**
- [ ] Tenant / user / request-id / locale stored in ContextVar; `set()` happens BEFORE any work that observes it
- [ ] Background tasks (Celery, FastAPI `BackgroundTasks`, raw `asyncio.create_task`, `ThreadPoolExecutor.submit`) re-establish security context; do not assume parent context propagates
- [ ] ORM auto-tenant filter (django-tenants, custom QuerySet manager) reads ContextVar with a fail-closed default - missing context raises, not silently queries all tenants
- [ ] Logging filters that read ContextVars (`request_id`, `user_id`) handle the unset case explicitly

## 6. Monkey-Patching at Import Time

**Red Flags:**
```python
# VULNERABLE - third-party "patch" library mutates stdlib at import
import gevent.monkey; gevent.monkey.patch_all()                    # only valid if FIRST import in process
import eventlet; eventlet.monkey_patch()
import some_test_lib                                                # silently patches socket, ssl

# VULNERABLE - import-order-dependent security
# auth_middleware patches `requests.adapters.HTTPAdapter.send` to add Authorization header.
# If `requests` is imported BEFORE the patch, calls bypass auth.

# VULNERABLE - shadowing builtins
def open(path): ...                                                # local override; later imports still see builtin
```

**Checklist:**
- [ ] `gevent.monkey.patch_all()` / `eventlet.monkey_patch()` is the FIRST executable line of the entry point; not buried in a sub-module
- [ ] Security-relevant patches (auth headers, TLS verify defaults) applied in a known import order; lock with `__init__.py` ordering or `sys.meta_path` instrumentation
- [ ] No production dependency that monkey-patches stdlib silently (audit `mock` usage outside tests; `responses` / `vcrpy` only in tests)
- [ ] No global `requests.Session` mutated at runtime to inject/strip auth - per-call config or wrapper class instead

## 7. Format-String / f-string Attribute Leak

**Red Flags:**
```python
# VULNERABLE - .format() lets attacker reach attributes via {0.__class__.__init__.__globals__[SECRET_KEY]}
template = "Hello {user}"                                          # static OK
template = user_input                                              # if user_input contains {0.__class__...}, leaks
template.format(user, settings)                                    # .format passes object access through {}

# Real attack:
"{0.__init__.__globals__[CONFIG][SECRET_KEY]}".format(some_app_object)

# VULNERABLE - logging with %-style on dict from request
logger.info("User %(name)s", request.json)                         # request.json["name"] used; OK so long as not f-string
logger.info(f"User {request.json['name']}")                        # str.format-style not used; OK
logger.info("User %s" % request.json["name"])                      # OK

# SAFE
template = "Hello {user}"                                          # static template
template.format(user=user_name)                                    # named, no positional object access

# SAFE - never let user input be the .format() FORMAT STRING
```

**Attack Scenario:** user supplies `{0.__init__.__globals__[CONFIG][SECRET_KEY]}` as a "name template"; `template.format(app_object)` returns `SECRET_KEY` value to the attacker.

**Checklist:**
- [ ] User input is never the format string passed to `str.format(...)` / `format_map(...)`; only the substituted value
- [ ] f-strings (`f"..."`) are evaluated at compile time - no `f-string injection`; but do not feed f-string text from user (compile via `eval` is a separate, worse problem)
- [ ] `Template(user_input).safe_substitute(...)` (string.Template) is preferred when a templated user-supplied string is required - no attribute access syntax
- [ ] Logger format strings do not depend on user input (no `logger.info(user_input, value)`)

## 8. Decimal vs Float for Money and Security Counters

**Red Flags:**
```python
# VULNERABLE - float arithmetic on money / quotas / rate limits accumulates error
balance = 0.1 + 0.2                                                # 0.30000000000000004
charged = round(amount * tax_rate, 2)                              # off by a cent at scale; refund/charge mismatches

# VULNERABLE - float comparison for "below limit"
if usage_count < limit:                                            # 1e16 + 1 == 1e16 in float; counter saturates
    process()

# SAFE
from decimal import Decimal, getcontext
getcontext().prec = 28
balance = Decimal("0.1") + Decimal("0.2")                          # exact 0.3
# Counters: integers, never float
```

**Checklist:**
- [ ] Money columns: `Numeric(precision, scale)` / `DECIMAL` in DB; Python `Decimal` in code; never `float`
- [ ] Rate-limit / quota counters are integers; comparisons exact
- [ ] Currency conversions go through `Decimal` with explicit rounding mode; rounding mode chosen per regulation (ROUND_HALF_EVEN typical, ROUND_HALF_UP for invoices)
- [ ] Stripe / payment-gateway amounts kept in minor units (cents) as int, not float dollars

## 9. Dict Ordering / Iteration-Order Assumptions

**Red Flags:**
```python
# VULNERABLE - signature input depends on dict iteration order
canonical = "&".join(f"{k}={v}" for k, v in params.items())        # Python 3.7+ preserves insertion order
sig = hmac(canonical)                                              # but caller may insert in different order than verifier

# VULNERABLE - JSON canonicalization for HMAC
body = json.dumps(payload)                                         # key order not guaranteed across libraries (orjson, ujson)
sig = hmac(body)
```

**Attack Scenario:** signing service serializes `{"a":1,"b":2}` -> `{"a":1,"b":2}`; verifier on a different runtime serializes `{"b":2,"a":1}`; signatures mismatch even on legitimate traffic. Or: attacker swaps key order to bypass a "canonical form" check.

**Checklist:**
- [ ] HMAC / signature input is a canonical, sorted serialization (`json.dumps(payload, sort_keys=True, separators=(",", ":"))`) or a defined CBOR/RFC8785 JCS encoder
- [ ] Webhook bodies signed using the **raw bytes** as received, not re-serialized server-side (see SKILL.md webhook section)
- [ ] No code relies on `dict` iteration order for cross-service contracts; only within a single Python process

## 10. Signal Handlers in Multi-Threaded Servers

**Red Flags:**
```python
# VULNERABLE - signal handler in a worker thread (only main thread receives signals)
import signal, threading
def handler(s, f): cleanup()                                       # never called in thread
threading.Thread(target=lambda: signal.signal(signal.SIGTERM, handler)).start()

# VULNERABLE - signal handler doing non-async-signal-safe work
def handler(s, f):
    logger.error("got signal")                                     # may deadlock if signal arrives while logger holds lock
    db.close()                                                     # ditto
```

**Checklist:**
- [ ] Signal handlers registered in the main thread only; in async apps prefer `loop.add_signal_handler`
- [ ] Signal handlers do minimal async-signal-safe work: set a flag, write a byte to a self-pipe; real cleanup happens outside the handler
- [ ] gunicorn / uvicorn graceful-shutdown hooks (`on_exit`, `lifespan` shutdown) used for cleanup, not raw `signal.signal`
- [ ] No `os.fork()` after threads have started (POSIX: child inherits one thread; locks held by other threads remain locked - deadlocks); use `multiprocessing` with `spawn` start method on Linux as well as macOS

## 11. Subprocess `env=` Inheritance

**Red Flags:**
```python
# VULNERABLE - inherits full os.environ (LD_PRELOAD, PYTHONPATH, AWS_*, etc.)
subprocess.run(["./worker"], check=True)                            # whole env inherited
subprocess.Popen(args, env={**os.environ, "X": "1"})                # explicit but still includes everything

# SAFE - allowlist
env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
subprocess.run(["./worker"], env=env, check=True)
```

**Checklist:**
- [ ] Spawned subprocesses get an explicit allowlisted env, not raw `os.environ`, when handling user-influenced commands
- [ ] `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `DYLD_*` not propagated to child processes that handle untrusted input
- [ ] Container images do not set `PYTHONPATH=/app:/tmp` or similar paths writable by the app user

## References

- Pickle is unsafe: https://docs.python.org/3/library/pickle.html#module-pickle
- PyTorch `weights_only`: https://pytorch.org/docs/stable/generated/torch.load.html
- PEP 703 (free-threaded Python): https://peps.python.org/pep-0703/
- str.format attack: https://lucumr.pocoo.org/2016/12/29/careful-with-str-format/
- ContextVars: https://docs.python.org/3/library/contextvars.html
- CVE-2007-4559 (tarfile): https://nvd.nist.gov/vuln/detail/CVE-2007-4559
