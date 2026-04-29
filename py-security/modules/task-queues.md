# Task Queue / Background Job Security Patterns

Optional module for the `/security` skill. Apply when the project uses background task processing (Celery, RQ, Dramatiq, Huey, Arq, or custom queue workers).

Covers: Celery, RQ (Redis Queue), Dramatiq, Huey, Arq, and custom implementations.

## 1. Serialization

**Red Flags:**
```python
# VULNERABLE - Celery default before 4.0 was pickle (RCE via crafted message)
app = Celery("myapp", broker="redis://localhost")
# No serializer configured = pickle in older versions

# VULNERABLE - explicit pickle
app.conf.task_serializer = "pickle"
app.conf.accept_content = ["pickle"]

# SAFE
app.conf.task_serializer = "json"
app.conf.result_serializer = "json"
app.conf.accept_content = ["json"]
```

```python
# VULNERABLE - RQ uses pickle by default for job arguments and results
from rq import Queue
q = Queue(connection=redis)
q.enqueue(process_data, complex_object)  # Pickled

# SAFER - serialize to JSON before enqueuing
q.enqueue(process_data, json.dumps(data))
```

**Checklist:**
- [ ] Task serializer is `json` (not `pickle`, `yaml`, or `msgpack` with untrusted data)
- [ ] Result serializer is `json`
- [ ] `accept_content` restricted to `["json"]` (rejects pickle-encoded messages from rogue producers)
- [ ] If pickle is required (complex objects), broker is network-isolated and producers are trusted
- [ ] RQ users: aware that pickle is the default; validate inputs if broker is shared

## 2. Task Argument Validation

**Red Flags:**
```python
# VULNERABLE - task trusts arguments blindly
@app.task
def delete_user(user_id):
    db.execute(f"DELETE FROM users WHERE id = '{user_id}'")  # SQL injection via queue

# VULNERABLE - task accepts arbitrary kwargs
@app.task
def process(**kwargs):
    model = kwargs["model"]
    exec(f"from app.models import {model}")  # RCE via queue message
```

**Checklist:**
- [ ] Task arguments treated as untrusted input (same validation as HTTP endpoints)
- [ ] SQL queries in tasks use parameterized queries
- [ ] No `eval()`, `exec()`, `__import__()` on task arguments
- [ ] Argument types validated at task entry (not just trusted from producer)
- [ ] Tasks do not accept arbitrary `**kwargs` from the queue

## 3. Privilege Boundaries

**Red Flags:**
```python
# VULNERABLE - worker runs as root or with full DB admin credentials
# docker-compose.yml:
#   worker:
#     user: root
#     environment:
#       DATABASE_URL: postgresql://postgres:password@db/app  # Superuser

# SAFE - worker has minimal privileges
#   worker:
#     user: appuser
#     environment:
#       DATABASE_URL: postgresql://worker:password@db/app  # Limited role
```

**Checklist:**
- [ ] Worker process runs as non-root user
- [ ] Worker DB credentials have minimal required permissions (not superuser)
- [ ] Worker has no access to secrets it does not need (API keys for unrelated services)
- [ ] Tasks that require elevated privileges are isolated in a separate queue with a dedicated worker
- [ ] Worker file system access is restricted (read-only where possible)

## 4. Result Backend Exposure

**Red Flags:**
```python
# VULNERABLE - results contain sensitive data, accessible by task ID
@app.task
def get_user_pii(user_id):
    user = db.get_user(user_id)
    return {"ssn": user.ssn, "dob": user.dob}  # Stored in Redis, accessible by task ID

# SAFE - return only status, fetch sensitive data through authenticated channel
@app.task
def process_user(user_id):
    do_work(user_id)
    return {"status": "complete", "user_id": user_id}
```

**Checklist:**
- [ ] Result backend does not store sensitive data (PII, tokens, credentials)
- [ ] Result backend access restricted (not world-readable Redis)
- [ ] Result expiry configured (results auto-deleted after TTL)
- [ ] Task IDs not guessable (UUID, not sequential integer)
- [ ] Result backend connection encrypted (TLS) if over network

## 5. Broker Security

**Checklist:**
- [ ] Broker requires authentication (Redis password, RabbitMQ credentials)
- [ ] Broker connection uses TLS in production
- [ ] Broker not exposed to public network (bind to internal interface only)
- [ ] Broker access limited to producer and consumer services (network policy / firewall)
- [ ] If Redis: `requirepass` set, `protected-mode` enabled, no `KEYS *` in production code

## 6. Task Rate Limiting and Abuse

**Checklist:**
- [ ] Tasks triggered by user input have rate limits (prevent queue flooding)
- [ ] Retry limits configured with backoff (no infinite retry loops)
- [ ] `max_retries` set explicitly (Celery default is 3, but some tasks should be 0)
- [ ] Dead letter queue or failure handler for tasks that exceed retries
- [ ] Task timeout (`time_limit` / `soft_time_limit`) set to prevent hung workers

## 7. Tenant/User Context in Workers

**Red Flags:**
```python
# VULNERABLE - task loses tenant context
@app.task
def send_report():
    users = db.get_all_users()  # Cross-tenant query, no scoping
    for user in users:
        email(user)

# SAFE - tenant context passed explicitly
@app.task
def send_report(tenant_id):
    users = db.get_users(tenant_id=tenant_id)
    for user in users:
        email(user)
```

**Checklist:**
- [ ] Tenant ID / user ID passed explicitly to tasks (not inherited from request context)
- [ ] Tasks enforce tenant isolation in all DB queries
- [ ] Cross-tenant tasks (scheduled jobs, maintenance) explicitly documented and authorized
- [ ] Audit logging in tasks includes the triggering user/system context
- [ ] Request context (IP, session) not assumed available in workers

## 8. Scheduled / Periodic Tasks

**Checklist:**
- [ ] Celery Beat / scheduler config not writable by the application (prevents schedule injection)
- [ ] Periodic tasks validated for idempotency (safe to run twice if beat overlaps)
- [ ] Schedule intervals have minimum bounds (no sub-second schedules from user config)
- [ ] Dynamic schedules (user-created) validated and sandboxed
- [ ] Cron expressions from user input validated against an allowlist or parser (no arbitrary system commands)

## 9. Logging and Monitoring

**Checklist:**
- [ ] Task failures logged with context (task name, args summary, traceback)
- [ ] Sensitive arguments redacted from logs (passwords, tokens, PII)
- [ ] Queue depth monitored (alert on backlog growth, indicates DoS or failure)
- [ ] Worker health monitored (detect crashed or hung workers)
- [ ] Failed task arguments not exposed in monitoring dashboards
